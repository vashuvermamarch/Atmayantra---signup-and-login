from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# Load variables from .env file
load_dotenv()

# Get DATABASE_URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

# Use it in SQLAlchemy engine
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
