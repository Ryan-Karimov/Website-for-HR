from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from config import *

engine = create_engine(database)