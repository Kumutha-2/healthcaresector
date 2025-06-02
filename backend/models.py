from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, LargeBinary,create_engine
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet 


Base = declarative_base()

engine = create_engine("postgresql://myuser:mypassword@localhost/healthcare_app_db")


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    encryption_key = Column(LargeBinary, nullable=False) 
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True) 

    creator = relationship("User", remote_side=[id], backref="created_users")

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def generate_encryption_key(self):
        self.encryption_key = Fernet.generate_key()

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False) 
    name = Column(String, index=True)
    dob = Column(String)
    address = Column(String)
    phone = Column(String)
    email = Column(String)
    mrn = Column(String, unique=True, index=True) 
    genetic_data = Column(String)
    diagnosis = Column(String)
    prescription_history = Column(String)
    basic_consent = Column(Boolean, default=False)
    contact_sharing_consent = Column(Boolean, default=False)

    user = relationship("User", backref="patient_profile")

class Doctor(Base):
    __tablename__ = 'doctors'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False)
    name = Column(String, index=True)
    department = Column(String)
    shift_time = Column(String)

    user = relationship("User", backref="doctor_profile")

class Staff(Base):
    __tablename__ = 'staff'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False)
    name = Column(String, index=True)
    department = Column(String)
    shift_time = Column(String)

    user = relationship("User", backref="staff_profile")

class Admin(Base): 
    __tablename__ = 'admins' 
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False)
    name = Column(String, index=True)

    user = relationship("User", backref="admin_profile")

class Analyst(Base):
    __tablename__ = 'analysts'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False)

    name = Column(String, index=True) 
    report_name = Column(String)
    analysis_period = Column(String)
    disease_prevalence_data = Column(String) 
    resource_utilization_data = Column(String) 
    treatment_efficacy_stats = Column(String) 
    public_health_trends = Column(String) 

    user = relationship("User", backref="analyst_profile")

class Researcher(Base):
    __tablename__ = 'researchers'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False)

    name = Column(String, index=True) 
    study_title = Column(String)
    research_area = Column(String)
    methodology_summary = Column(String) 
    key_findings = Column(String) 
    anonymized_dataset_reference = Column(String)
    publication_link = Column(String)

    user = relationship("User", backref="researcher_profile")

Base.metadata.create_all(engine)