from sqlalchemy import Column, Integer, String, Enum
from app.database import Base
import enum

class UserType(str, enum.Enum):
    USER = "User"
    YOGA_INSTRUCTOR = "Yoga Trainer"
    YOGA_DOCTOR = "Yoga Doctor"
    PHYSIOTHERAPIST = "Physiotherapist"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone_number = Column(String, unique=True, index=True, nullable=False)  # <-- Added
    hashed_password = Column(String, nullable=False)
    user_type = Column(Enum(UserType), nullable=False)
