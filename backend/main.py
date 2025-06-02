from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from backend import models, auth, encryption
from backend.database import SessionLocal, engine, init_db, get_db


try:
    init_db()
except Exception as e:
    print(f"Error during initial DB setup (might be okay if DB is already set up): {e}")


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserBase(BaseModel):
    username: str
    role: str

class UserDisplay(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str
    name: Optional[str] = None
    department: Optional[str] = None
    shift_time: Optional[str] = None

class AdminUserCreateRequest(UserCreateRequest): 
    admin_username: str 
    admin_password: str 

class PatientRegistrationRequest(BaseModel):
    name: str
    dob: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    mrn: str
    genetic_data: Optional[str] = None
    basic_consent: bool = False
    contact_sharing_consent: bool = False
    staff_username: str 

class PatientUpdateRequest(PatientRegistrationRequest): 
    pass

class PatientListItem(BaseModel): 
    user_id: int
    username: str 
    display_name: str 
    mrn: str 

    class Config:
        orm_mode = True

class UserDetailsEditRequest(BaseModel):
    name: Optional[str] = None
    department: Optional[str] = None
    shift_time: Optional[str] = None
    admin_username: Optional[str] = None
    admin_password: Optional[str] = None

class PatientMedicalDataRequest(BaseModel):
    patient_user_id: int
    diagnosis: Optional[str] = None
    prescription_history: Optional[str] = None
    basic_consent: bool 
    contact_sharing_consent: bool 
    doctor_username: str 

class AnalystDataSubmitRequest(BaseModel):
    report_name: str
    analysis_period: Optional[str] = None
    disease_prevalence_data: Optional[str] = None
    resource_utilization_data: Optional[str] = None
    treatment_efficacy_stats: Optional[str] = None 
    public_health_trends: Optional[str] = None

class ResearcherDataSubmitRequest(BaseModel):
    study_title: str
    research_area: Optional[str] = None
    methodology_summary: Optional[str] = None
    key_findings: Optional[str] = None 
    anonymized_dataset_reference: Optional[str] = None
    publication_link: Optional[str] = None


async def get_current_active_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    username = request.headers.get("X-Username")
    if not username: 
        return None 
    
    user = auth.get_user_by_username(db, username=username)
    if not user or not user.is_active:
        return None
    return user


def encrypt_model_fields(db_item: Any, key: bytes, consent_basic: bool, consent_contact: bool, fields_to_encrypt: List[str]):
    for field in fields_to_encrypt:
        if hasattr(db_item, field):
            value = getattr(db_item, field)
            if value is not None and isinstance(value, str):
                encrypted_value = value 
                if consent_basic: 
                    encrypted_value = encryption.encrypt_data(value, key)
                elif consent_contact:
                    field_type = 'other'
                    if field == 'phone': field_type = 'phone'
                    elif field == 'email': field_type = 'email'
                    encrypted_value = encryption.partial_encrypt_data(value, field_type, key)
                else: 
                    encrypted_value = encryption.encrypt_data(value, key) 
                setattr(db_item, field, encrypted_value)

def decrypt_model_fields(data_dict: Dict, key: bytes, consent_basic: bool, consent_contact: bool, fields_to_decrypt: List[str]):
    decrypted_dict = data_dict.copy()
    for field in fields_to_decrypt:
        if field in decrypted_dict and decrypted_dict[field] is not None:
            value = decrypted_dict[field]
            decrypted_value = value 
            if consent_basic or consent_contact: 
                field_type = 'other'
                if field == 'phone': field_type = 'phone'
                elif field == 'email': field_type = 'email'
                decrypted_value = encryption.partial_decrypt_data(value, field_type, key)
            else: 
                decrypted_value = encryption.decrypt_data(value, key) 
            decrypted_dict[field] = decrypted_value
    return decrypted_dict

PATIENT_SENSITIVE_FIELDS = ["name", "dob", "address", "phone", "email", "mrn", "genetic_data", "diagnosis", "prescription_history"]
STAFF_DOCTOR_SENSITIVE_FIELDS = ["name", "department", "shift_time"]
ANALYST_SENSITIVE_FIELDS = ["name", "report_name", "analysis_period", "disease_prevalence_data", "resource_utilization_data", "treatment_efficacy_stats", "public_health_trends"]
RESEARCHER_SENSITIVE_FIELDS = ["name", "study_title", "research_area", "methodology_summary", "key_findings", "anonymized_dataset_reference", "publication_link"]


@app.post("/login", response_model=UserDisplay)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, username=request.username, password=request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.role == "patient" and not user.is_active: 
        raise HTTPException(status_code=403, detail="Patients cannot login directly or account inactive.")
    return user

@app.post("/register_user_by_admin", response_model=UserDisplay)
async def register_user_by_admin(request: AdminUserCreateRequest, db: Session = Depends(get_db)):
    admin = auth.authenticate_user(db, username=request.admin_username, password=request.admin_password)
    if not admin or admin.role != "admin":
        raise HTTPException(status_code=403, detail="Invalid admin credentials or not an admin.")

    if request.role.lower() not in ["staff", "doctor"]:
        raise HTTPException(status_code=400, detail="Admin can only register staff or doctors via this endpoint.")

    user_details = {
        "name": request.name,
        "department": request.department,
        "shift_time": request.shift_time
    }
    new_user, message = auth.create_user_account(
        db,
        username=request.username,
        password=request.password,
        role=request.role,
        created_by_user_id=admin.id,
        details=user_details
    )
    if not new_user:
        raise HTTPException(status_code=400, detail=message)
    
    profile_model = models.Staff if new_user.role == "staff" else models.Doctor
    profile = db.query(profile_model).filter(profile_model.user_id == new_user.id).first()
    if profile:
        encrypt_model_fields(profile, new_user.encryption_key, True, False, STAFF_DOCTOR_SENSITIVE_FIELDS) 
        db.commit()

    return new_user

@app.post("/register_self", response_model=UserDisplay) 
async def register_self(request: UserCreateRequest, db: Session = Depends(get_db)):
    if request.role.lower() not in ["analyst", "researcher"]:
        raise HTTPException(status_code=400, detail="Self-registration only for Analyst or Researcher.")
    
    user_details = {"name": request.name if request.name else request.username} 

    new_user, message = auth.create_user_account(
        db,
        username=request.username,
        password=request.password,
        role=request.role,
        details=user_details 
    )
    if not new_user:
        raise HTTPException(status_code=400, detail=message)
    
    profile_model = None
    if new_user.role == "analyst": profile_model = models.Analyst
    elif new_user.role == "researcher": profile_model = models.Researcher
    
    if profile_model:
        profile = db.query(profile_model).filter(profile_model.user_id == new_user.id).first()
        if profile and hasattr(profile, "name"): 
             encrypt_model_fields(profile, new_user.encryption_key, True, False, ["name"])
             db.commit()
             
    return new_user


@app.post("/staff/register_patient", response_model=UserDisplay)
async def staff_register_patient(request_data: PatientRegistrationRequest, db: Session = Depends(get_db)):
    staff_user = auth.get_user_by_username(db, request_data.staff_username)
    if not staff_user or staff_user.role != "staff":
        raise HTTPException(status_code=403, detail="Only staff can register patients.")

    existing_patient_record = db.query(models.Patient).filter(models.Patient.mrn == request_data.mrn).first()
    if existing_patient_record:
        patient_user_for_mrn = db.query(models.User).filter(models.User.id == existing_patient_record.user_id).first()
        if patient_user_for_mrn and patient_user_for_mrn.username != request_data.name: 
             raise HTTPException(status_code=400, detail=f"MRN {request_data.mrn} is already associated with a different patient.")
        raise HTTPException(status_code=400, detail=f"A patient with MRN {request_data.mrn} already exists.")

    patient_username = f"patient_{request_data.mrn}" 
    if auth.get_user_by_username(db, patient_username):
        patient_username = f"patient_{request_data.mrn}_{datetime.now().strftime('%S%f')}"

    patient_user, message = auth.create_user_account(
        db,
        username=patient_username, 
        password=f"patient_default_pass_{request_data.mrn}",
        role="patient",
        created_by_user_id=staff_user.id
    )
    if not patient_user:
        raise HTTPException(status_code=500, detail=f"Failed to create patient user account: {message}")

    patient_profile_data = request_data.dict(exclude={"staff_username"})
    patient_profile = models.Patient(user_id=patient_user.id, **patient_profile_data)
    
    encrypt_model_fields(
        patient_profile,
        patient_user.encryption_key,
        request_data.basic_consent,
        request_data.contact_sharing_consent,
        PATIENT_SENSITIVE_FIELDS
    )
    db.add(patient_profile)
    db.commit()
    db.refresh(patient_user)
    return patient_user


@app.put("/staff/edit_patient/{patient_user_id}", response_model=UserDisplay)
async def staff_edit_patient(patient_user_id: int, request_data: PatientUpdateRequest, db: Session = Depends(get_db)):
    staff_user = auth.get_user_by_username(db, request_data.staff_username) 
    if not staff_user or staff_user.role != "staff":
        raise HTTPException(status_code=403, detail="Only staff can edit patients.")

    patient_user = auth.get_user_by_id(db, patient_user_id)
    if not patient_user or patient_user.role != "patient":
        raise HTTPException(status_code=404, detail="Patient not found.")

    patient_profile = db.query(models.Patient).filter(models.Patient.user_id == patient_user_id).first()
    if not patient_profile:
        raise HTTPException(status_code=404, detail="Patient profile not found.")

    update_data = request_data.dict(exclude_unset=True, exclude={"staff_username"})
    for key, value in update_data.items():
        if hasattr(patient_profile, key):
            setattr(patient_profile, key, value)
    
    encrypt_model_fields(
        patient_profile,
        patient_user.encryption_key,
        request_data.basic_consent, 
        request_data.contact_sharing_consent,
        PATIENT_SENSITIVE_FIELDS
    )
    db.commit()
    db.refresh(patient_user)
    return patient_user


@app.put("/admin/edit_user_details/{user_to_edit_id}", response_model=UserDisplay)
async def admin_edit_user_details(user_to_edit_id: int, request_data: UserDetailsEditRequest, db: Session = Depends(get_db)):
    admin_user = auth.authenticate_user(db, username=request_data.admin_username, password=request_data.admin_password)
    if not admin_user or admin_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin authentication failed.")

    user_to_edit = auth.get_user_by_id(db, user_to_edit_id)
    if not user_to_edit or user_to_edit.role not in ["staff", "doctor"]: 
        raise HTTPException(status_code=404, detail="User to edit not found or not editable by admin.")

    profile_model = None
    if user_to_edit.role == "staff":
        profile_model = models.Staff
    elif user_to_edit.role == "doctor":
        profile_model = models.Doctor
    
    if not profile_model:
         raise HTTPException(status_code=400, detail=f"No profile type defined for role {user_to_edit.role}")


    profile = db.query(profile_model).filter(profile_model.user_id == user_to_edit_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail=f"{user_to_edit.role.capitalize()} profile not found.")

    updated = False
    if request_data.name is not None:
        profile.name = request_data.name
        updated = True
    if request_data.department is not None:
        profile.department = request_data.department
        updated = True
    if request_data.shift_time is not None:
        profile.shift_time = request_data.shift_time
        updated = True
    
    if updated:
        encrypt_model_fields(profile, user_to_edit.encryption_key, True, False, STAFF_DOCTOR_SENSITIVE_FIELDS) 
        db.commit()
        db.refresh(user_to_edit)
    return user_to_edit


@app.post("/doctor/submit_patient_medical_data")
async def doctor_submit_patient_medical_data(request_data: PatientMedicalDataRequest, db: Session = Depends(get_db)):
    doctor_user = auth.get_user_by_username(db, request_data.doctor_username) 
    if not doctor_user or doctor_user.role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can submit medical data.")

    patient_user = auth.get_user_by_id(db, request_data.patient_user_id)
    if not patient_user or patient_user.role != "patient":
        raise HTTPException(status_code=404, detail="Patient not found.")

    patient_profile = db.query(models.Patient).filter(models.Patient.user_id == patient_user.id).first()
    if not patient_profile:
        raise HTTPException(status_code=404, detail="Patient profile not found.")

    if request_data.diagnosis is not None:
        patient_profile.diagnosis = request_data.diagnosis
    if request_data.prescription_history is not None:
        patient_profile.prescription_history = request_data.prescription_history
    
    patient_profile.basic_consent = request_data.basic_consent
    patient_profile.contact_sharing_consent = request_data.contact_sharing_consent

    encrypt_model_fields(
        patient_profile,
        patient_user.encryption_key,
        patient_profile.basic_consent, 
        patient_profile.contact_sharing_consent,
        ["diagnosis", "prescription_history"] 
    )
    db.commit()
    return {"message": "Medical data submitted successfully."}



@app.get("/patients_list_for_doctor", response_model=List[PatientListItem]) 
async def get_patients_list_for_doctor(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):

    
    patient_users_with_profiles = db.query(
        models.User, models.Patient
    ).join(models.Patient, models.User.id == models.Patient.user_id)\
     .filter(models.User.role == "patient").all()

    patient_list_items = []
    for user, patient_profile in patient_users_with_profiles:
        if patient_profile:
            decrypted_name = encryption.decrypt_data(patient_profile.name, user.encryption_key) \
                if patient_profile.name else user.username 
            
            
            patient_list_items.append(
                PatientListItem(
                    user_id=user.id,
                    username=user.username, 
                    display_name=decrypted_name,
                    mrn=encryption.decrypt_data(patient_profile.mrn, user.encryption_key) if patient_profile.mrn else "N/A" # Also decrypt MRN
                )
            )
        else:
            patient_list_items.append(
                PatientListItem(
                    user_id=user.id,
                    username=user.username,
                    display_name=user.username, 
                    mrn="Profile Missing"
                )
            )
            
    return patient_list_items


@app.get("/view_patient_data/{patient_user_id}", response_model=Dict)
async def view_patient_data(patient_user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    if not current_user or current_user.role not in ["staff", "doctor", "admin"]: 
         raise HTTPException(status_code=403, detail="Access denied.")

    patient_user = auth.get_user_by_id(db, patient_user_id)
    if not patient_user or patient_user.role != "patient":
        raise HTTPException(status_code=404, detail="Patient not found.")

    patient_profile = db.query(models.Patient).filter(models.Patient.user_id == patient_user_id).first()
    if not patient_profile:
        raise HTTPException(status_code=404, detail="Patient profile data not found.")

    profile_dict = {c.name: getattr(patient_profile, c.name) for c in patient_profile.__table__.columns}
    
    decrypted_data = decrypt_model_fields(
        profile_dict,
        patient_user.encryption_key,
        patient_profile.basic_consent,
        patient_profile.contact_sharing_consent,
        PATIENT_SENSITIVE_FIELDS
    )
    return decrypted_data

@app.get("/view_user_profile_data/{user_id_to_view}", response_model=Dict)
async def view_user_profile_data(user_id_to_view: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    if not current_user: 
        raise HTTPException(status_code=401, detail="Authentication required.")
    
    user_to_view = auth.get_user_by_id(db, user_id_to_view)
    if not user_to_view:
        raise HTTPException(status_code=404, detail="User to view not found.")

    can_view = False
    if current_user.id == user_to_view.id: 
        can_view = True
    elif current_user.role == "admin" and user_to_view.role in ["staff", "doctor", "analyst", "researcher"]: 
        can_view = True

    if not can_view:
        raise HTTPException(status_code=403, detail="You do not have permission to view this user's data.")

    profile_data = None
    fields_to_decrypt_list = []

    if user_to_view.role == "staff":
        profile = db.query(models.Staff).filter(models.Staff.user_id == user_to_view.id).first()
        fields_to_decrypt_list = STAFF_DOCTOR_SENSITIVE_FIELDS
    elif user_to_view.role == "doctor":
        profile = db.query(models.Doctor).filter(models.Doctor.user_id == user_to_view.id).first()
        fields_to_decrypt_list = STAFF_DOCTOR_SENSITIVE_FIELDS
    elif user_to_view.role == "analyst":
        profile = db.query(models.Analyst).filter(models.Analyst.user_id == user_to_view.id).first()
        fields_to_decrypt_list = ANALYST_SENSITIVE_FIELDS 
    elif user_to_view.role == "researcher":
        profile = db.query(models.Researcher).filter(models.Researcher.user_id == user_to_view.id).first()
        fields_to_decrypt_list = RESEARCHER_SENSITIVE_FIELDS
    else:
        raise HTTPException(status_code=400, detail=f"No profile view defined for role {user_to_view.role}")

    if not profile:
        raise HTTPException(status_code=404, detail=f"{user_to_view.role.capitalize()} profile data not found.")

    profile_dict = {c.name: getattr(profile, c.name) for c in profile.__table__.columns}
    
    decrypted_data = decrypt_model_fields(
        profile_dict,
        user_to_view.encryption_key,
        True, 
        False,
        fields_to_decrypt_list
    )
    return decrypted_data

@app.post("/analyst/submit_data", response_model=Dict)
async def analyst_submit_data(
    data: AnalystDataSubmitRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    if not current_user or current_user.role != "analyst":
        raise HTTPException(status_code=403, detail="Only analysts can submit analyst data.")

    analyst_profile = db.query(models.Analyst).filter(models.Analyst.user_id == current_user.id).first()
    if not analyst_profile:
        analyst_profile = models.Analyst(user_id=current_user.id, name=current_user.username)
        db.add(analyst_profile)
        db.flush() 

    analyst_profile.report_name = data.report_name
    if data.analysis_period: analyst_profile.analysis_period = data.analysis_period
    if data.disease_prevalence_data: analyst_profile.disease_prevalence_data = data.disease_prevalence_data
    if data.resource_utilization_data: analyst_profile.resource_utilization_data = data.resource_utilization_data
    if data.treatment_efficacy_stats: analyst_profile.treatment_efficacy_stats = data.treatment_efficacy_stats
    if data.public_health_trends: analyst_profile.public_health_trends = data.public_health_trends
    
    encrypt_model_fields(
        analyst_profile,
        current_user.encryption_key,
        True, 
        False,
        ANALYST_SENSITIVE_FIELDS
    )
    
    db.commit()
    return {"message": "Analyst data submitted successfully."}


@app.post("/researcher/submit_data", response_model=Dict)
async def researcher_submit_data(
    data: ResearcherDataSubmitRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    if not current_user or current_user.role != "researcher":
        raise HTTPException(status_code=403, detail="Only researchers can submit research data.")

    researcher_profile = db.query(models.Researcher).filter(models.Researcher.user_id == current_user.id).first()
    if not researcher_profile:
        researcher_profile = models.Researcher(user_id=current_user.id, name=current_user.username)
        db.add(researcher_profile)
        db.flush()

    researcher_profile.study_title = data.study_title
    if data.research_area: researcher_profile.research_area = data.research_area
    if data.methodology_summary: researcher_profile.methodology_summary = data.methodology_summary
    if data.key_findings: researcher_profile.key_findings = data.key_findings
    if data.anonymized_dataset_reference: researcher_profile.anonymized_dataset_reference = data.anonymized_dataset_reference
    if data.publication_link: researcher_profile.publication_link = data.publication_link

    encrypt_model_fields(
        researcher_profile,
        current_user.encryption_key,
        True, 
        False,
        RESEARCHER_SENSITIVE_FIELDS
    )
    
    db.commit()
    return {"message": "Researcher data submitted successfully."}


@app.get("/view_user_profile_data/{user_id_to_view}", response_model=Dict)
async def view_user_profile_data(user_id_to_view: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required. Please login.")
    
    user_to_view = auth.get_user_by_id(db, user_id_to_view)
    if not user_to_view:
        raise HTTPException(status_code=404, detail="User to view not found.")

    can_view = False
    if current_user.id == user_to_view.id:
        can_view = True
    elif current_user.role == "admin" and user_to_view.role in ["staff", "doctor", "analyst", "researcher"]: 
        can_view = True
    
    if not can_view:
        raise HTTPException(status_code=403, detail="You do not have permission to view this user's data.")

    profile = None 
    fields_to_decrypt_list = []

    if user_to_view.role == "staff":
        profile = db.query(models.Staff).filter(models.Staff.user_id == user_to_view.id).first()
        fields_to_decrypt_list = STAFF_DOCTOR_SENSITIVE_FIELDS
    elif user_to_view.role == "doctor":
        profile = db.query(models.Doctor).filter(models.Doctor.user_id == user_to_view.id).first()
        fields_to_decrypt_list = STAFF_DOCTOR_SENSITIVE_FIELDS
    elif user_to_view.role == "analyst":
        profile = db.query(models.Analyst).filter(models.Analyst.user_id == user_to_view.id).first()
        fields_to_decrypt_list = ANALYST_SENSITIVE_FIELDS
    elif user_to_view.role == "researcher":
        profile = db.query(models.Researcher).filter(models.Researcher.user_id == user_to_view.id).first()
        fields_to_decrypt_list = RESEARCHER_SENSITIVE_FIELDS
    elif user_to_view.role == "admin": 
        profile = db.query(models.Admin).filter(models.Admin.user_id == user_to_view.id).first()
        fields_to_decrypt_list = ["name"] 
    else:
        if user_to_view.role == "patient":
             raise HTTPException(status_code=400, detail=f"To view patient data, use the /view_patient_data/{{patient_user_id}} endpoint.")
        raise HTTPException(status_code=400, detail=f"No profile view defined for role {user_to_view.role} via this endpoint.")

    if not profile:
        raise HTTPException(status_code=404, detail=f"{user_to_view.role.capitalize()} profile data not found.")


    profile_dict = {c.name: getattr(profile, c.name) for c in profile.__table__.columns if hasattr(profile, c.name)}
    
    decrypted_data = decrypt_model_fields(
        profile_dict,
        user_to_view.encryption_key,
        True, 
        False,
        fields_to_decrypt_list
    )
    decrypted_data['user_info'] = {
        "id": user_to_view.id,
        "username": user_to_view.username,
        "role": user_to_view.role
    }
    return decrypted_data



@app.get("/users", response_model=List[UserDisplay]) 
async def get_all_users(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    users = db.query(models.User).all()
    return users

@app.get("/")
async def root():
    return {"message": "Healthcare Data API with Per-User Encryption is running"}
