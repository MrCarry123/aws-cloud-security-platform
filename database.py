from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://anshchaudhary@localhost:5432/cloud_security"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)