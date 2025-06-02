from backend.models import User, Staff, Doctor, Admin as AdminProfile, Analyst, Researcher 
from backend.database import SessionLocal
from sqlalchemy.orm import Session

def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if user and user.check_password(password) and user.is_active:
        return user
    return None

def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()

def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id).first()

def create_user_account(db: Session, username: str, password: str, role: str,
                        created_by_user_id: int | None = None,
                        details: dict | None = None) -> tuple[User | None, str]:
    existing_user = get_user_by_username(db, username)
    if existing_user:
        return None, "Username already exists"

    try:
        new_user = User(
            username=username,
            role=role.lower(),
            created_by_user_id=created_by_user_id
        )
        new_user.set_password(password)
        new_user.generate_encryption_key() 
        db.add(new_user)
        db.flush() 

        if details:
            profile_name = details.get("name", username) 
            if new_user.role == "staff":
                staff_profile = Staff(
                    user_id=new_user.id,
                    name=profile_name,
                    department=details.get("department"),
                    shift_time=details.get("shift_time")
                )
                db.add(staff_profile)
            elif new_user.role == "doctor":
                doctor_profile = Doctor(
                    user_id=new_user.id,
                    name=profile_name,
                    department=details.get("department"),
                    shift_time=details.get("shift_time")
                )
                db.add(doctor_profile)
            elif new_user.role == "admin": 
                 admin_p = AdminProfile(user_id=new_user.id, name=profile_name)
                 db.add(admin_p)
            elif new_user.role == "analyst":
                analyst_p = Analyst(user_id=new_user.id, name=profile_name) 
                db.add(analyst_p)
            elif new_user.role == "researcher":
                researcher_p = Researcher(user_id=new_user.id, name=profile_name) 
                db.add(researcher_p)

        db.commit()
        db.refresh(new_user)
        return new_user, "User created successfully"
    except Exception as e:
        db.rollback()
        return None, f"Error creating user: {str(e)}"