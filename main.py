from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database.session import get_session, create_tables
from models.user import User, UserCreate
from models.patient import Patient, PatientCreate, PatientUpdate
from models.audit_log import AuditLog

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_admin,
    get_current_doctor,
    get_receptionist_or_above,
)

app = FastAPI(
    title="ClinicGuard API",
    version="1.0.0"
)




create_tables()

def log_action(
    session: Session,
    user: User,
    action: str,
    patient_id: int = None
):
    log = AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        patient_id=patient_id
    )

    session.add(log)
    session.commit()



limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)



@app.get("/")
def home():
    return {
        "message": "Welcome to ClinicGuard API"
    }




@app.post("/register", status_code=201)
@limiter.limit("5/minute")
def register_user(
    request: Request,
    user_data: UserCreate,
    session: Session = Depends(get_session)
):

    existing = session.exec(
        select(User).where(User.username == user_data.username)
    ).first()

    if existing:
        raise HTTPException(409, "Username already exists")

    existing = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()

    if existing:
        raise HTTPException(409, "Email already exists")

    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return {
        "message": "User created successfully",
        "user": db_user,
    }




@app.post("/login")
@limiter.limit("5/minute")
def login_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):

    user = session.exec(
        select(User).where(User.username == form_data.username)
    ).first()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    if not verify_password(
        form_data.password,
        user.hashed_password,
    ):
        raise HTTPException(401, "Invalid credentials")

    if not user.is_active:
        raise HTTPException(403, "User is inactive")

    user.last_login = datetime.utcnow()

    session.commit()

    token = create_access_token(
        {"sub": user.username}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 1800,
        "username": user.username,
        "role": user.role,
    }
    
    

@app.post("/patients", status_code=201)
@limiter.limit("20/hour")
def create_patient(
    request: Request,
    patient_data: PatientCreate,
    current_user: User = Depends(get_receptionist_or_above),
    session: Session = Depends(get_session)
):
    """Create a new patient record."""

    if patient_data.doctor_id:
        doctor = session.get(User, patient_data.doctor_id)

        if not doctor:
            raise HTTPException(404, "Doctor not found")

        if doctor.role not in ["admin", "doctor"]:
            raise HTTPException(400, "Assigned user must be a doctor")

    db_patient = Patient(
        **patient_data.model_dump(),
        created_by=current_user.id
    )

   session.add(db_patient)
session.commit()
session.refresh(db_patient)

log_action(
    session,
    current_user,
    "Created patient",
    db_patient.id
)

return db_patient


@app.get("/patients")
@limiter.limit("30/minute")
def list_patients(
    request: Request,
    current_user: User = Depends(get_receptionist_or_above),
    session: Session = Depends(get_session)
):
    """List all patients."""

    query = select(Patient)

    if current_user.role == "doctor":
        query = query.where(Patient.doctor_id == current_user.id)

    return session.exec(query).all()


@app.get("/patients/{patient_id}")
@limiter.limit("30/minute")
def get_patient(
    request: Request,
    patient_id: int,
    current_user: User = Depends(get_receptionist_or_above),
    session: Session = Depends(get_session)
):
    """Get one patient."""

    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(404, "Patient not found")

    if current_user.role == "doctor" and patient.doctor_id != current_user.id:
        raise HTTPException(403, "Access denied to this patient record")

    return patient


@app.patch("/patients/{patient_id}")
def update_patient(
    patient_id: int,
    patient_update: PatientUpdate,
    current_user: User = Depends(get_current_doctor),
    session: Session = Depends(get_session)
):
    """Update a patient."""

    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(404, "Patient not found")

    if current_user.role != "admin" and patient.doctor_id != current_user.id:
        raise HTTPException(403, "You can only update your own patients")

    for key, value in patient_update.model_dump(exclude_unset=True).items():
        setattr(patient, key, value)

    patient.updated_at = datetime.utcnow()

    session.commit()
    session.refresh(patient)

    return patient
    
    
@app.patch("/patients/{patient_id}/assign")
def assign_patient(
    patient_id: int,
    current_user: User = Depends(get_current_doctor),
    session: Session = Depends(get_session)
):
    """Allow a doctor to claim an unassigned patient."""

    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    if patient.doctor_id is not None:
        raise HTTPException(
            status_code=400,
            detail="Patient is already assigned to a doctor"
        )

    patient.doctor_id = current_user.id
    patient.updated_at = datetime.utcnow()

    session.commit()
    session.refresh(patient)

    log_action(
        session,
        current_user,
        "Assigned patient",
        patient.id
    )

    return {
        "message": "Patient assigned successfully",
        "patient": patient
    }   



@app.get("/patients/search")
def search_patients(
    name: str,
    current_user: User = Depends(get_receptionist_or_above),
    session: Session = Depends(get_session)
):
    """Search patients by first or last name."""

    query = select(Patient).where(
        (Patient.first_name.contains(name)) |
        (Patient.last_name.contains(name))
    )

    # Doctors can only search their own patients
    if current_user.role == "doctor":
        query = query.where(
            Patient.doctor_id == current_user.id
        )

    patients = session.exec(query).all()

    log_action(
        session,
        current_user,
        f"Searched patients for '{name}'"
    )

    return patients    


@app.delete("/patients/{patient_id}")
def delete_patient(
    patient_id: int,
    admin: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    """Delete a patient (admin only)."""

    patient = sessi
    on.get(Patient, patient_id)

    if not patient:
        raise HTTPException(404, "Patient not found")

    session.delete(patient)
    session.commit()

    return {"message": "Patient record deleted"}
    
    
    

@app.get("/users")
def list_users(
    admin: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    """List all users (Admin only)."""
    return session.exec(select(User)).all()


@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    admin: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    """Get one user (Admin only)."""

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(404, "User not found")

    return user


@app.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    new_role: str,
    admin: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    """Update a user's role."""

    if new_role not in ["admin", "doctor", "receptionist"]:
        raise HTTPException(400, "Invalid role")

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(404, "User not found")

    if user.id == admin.id:
        raise HTTPException(400, "You cannot change your own role")

    user.role = new_role

    session.commit()

    return {
        "message": f"User {user.username} role updated to {new_role}"
    }


@app.patch("/users/{user_id}/activate")
def toggle_user_activation(
    user_id: int,
    activate: bool,
    admin: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    """Activate or deactivate a user."""

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(404, "User not found")

    if user.id == admin.id:
        raise HTTPException(400, "You cannot deactivate yourself")

    user.is_active = activate

    session.commit()

    return {
        "message": f"User {user.username} activation set to {activate}"
    }