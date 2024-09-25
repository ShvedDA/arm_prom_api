from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlitecloud://nwlpofyrhk.sqlite.cloud:8860/arm_prom_consulting.db?apikey=1B5V53Ib3BdX81ytmbHXCoaxqK3WuQOEXBCZ7mBXzPo"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()




