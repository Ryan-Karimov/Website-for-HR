from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from config import *

DATABASE_URL = database
engine = create_engine(DATABASE_URL)

db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))