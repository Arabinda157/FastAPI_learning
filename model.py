from database import Base,engine
from sqlalchemy import String,Column,Integer,func,ForeignKey,DateTime
from sqlalchemy.dialects.mysql import  TINYINT, VARCHAR 

# class User(Base):
#     __tablename__="users"
#     id=column(Integer,primarykey=True)

class MgUser(Base):
    __tablename__ = 'mg_users'
    id = Column(Integer, primary_key=True)
    user_name = Column(String(255))
    email = Column(String(255))
    hashed_password = Column(String(255))
    is_deleted = Column(TINYINT(1),default=0)

class MgVerificationCode(Base):
    __tablename__ = 'mg_verification_code'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('mg_users.id')) # type: ignore
    code = Column(String(6), nullable=False)
    created_at = Column(DateTime, default=func.now())

Base.metadata.create_all(bind=engine)