from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

DATABASE_URL = "postgresql://myuser:mypassword@localhost/healthcare_app_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from backend import models
    models.Base.metadata.create_all(bind=engine)
    print("Database tables created (if they didn't exist).")

    db = SessionLocal()
    try:
        admin_user = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin_user:
            print("Creating initial admin user...")
            new_admin = models.User(
                username="admin",
                role="admin",
            )
            new_admin.set_password("admin123") 
            new_admin.generate_encryption_key()
            db.add(new_admin)
            
            db.flush() 

            if new_admin.id: 
                admin_profile = models.Admin(user_id=new_admin.id, name=new_admin.username)
                db.add(admin_profile)
                db.commit() 
                print("Initial admin user (admin/admin123) created with an encryption key and profile.")
            else:
                db.rollback() 
                print("Error: Could not get ID for new admin user. Admin profile not created.")
        else:
            print("Admin user (admin) already exists.")
    except Exception as e:
        db.rollback()
        print(f"Error creating initial admin user: {e}")
    finally:
        db.close()