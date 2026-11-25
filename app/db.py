import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, JSON, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./aisx_security.db')
opts={'connect_args': {'check_same_thread':False}} if DATABASE_URL.startswith('sqlite') else {'pool_pre_ping':True}
engine=create_engine(DATABASE_URL, **opts)
SessionLocal=sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base=declarative_base()
def now(): return datetime.now(timezone.utc)
class Tenant(Base):
    __tablename__='tenants'
    id=Column(Integer, primary_key=True); name=Column(String(120), unique=True, nullable=False)
class User(Base):
    __tablename__='users'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,ForeignKey('tenants.id'),nullable=False,index=True)
    username=Column(String(120),nullable=False); password_hash=Column(String(400),nullable=False)
    role=Column(String(30),nullable=False); active=Column(Boolean,default=True)
    __table_args__=(UniqueConstraint('tenant_id','username'),)
class Event(Base):
    __tablename__='events'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,nullable=False,index=True)
    category=Column(String(48),nullable=False); actor=Column(String(120),nullable=False)
    action=Column(String(100),nullable=False); result=Column(String(40),nullable=False)
    detail=Column(JSON,nullable=False,default=dict); at=Column(DateTime(timezone=True),default=now)
    prev_hash=Column(String(64),nullable=False); entry_hash=Column(String(64),nullable=False)
class ToolRequest(Base):
    __tablename__='tool_requests'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,index=True,nullable=False)
    requester_id=Column(Integer,nullable=False); tool=Column(String(90),nullable=False)
    purpose=Column(String(400),nullable=False); status=Column(String(40),nullable=False)
    approver_id=Column(Integer,nullable=True); created=Column(DateTime(timezone=True),default=now)
class Asset(Base):
    __tablename__='assets'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,index=True,nullable=False)
    name=Column(String(160),nullable=False); owner=Column(String(120),nullable=False)
    config=Column(JSON,nullable=False); assessment=Column(JSON,nullable=False)
class Alert(Base):
    __tablename__='alerts'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,index=True,nullable=False)
    title=Column(String(160),nullable=False); signal=Column(JSON,nullable=False); triage=Column(JSON,nullable=False)
    status=Column(String(25),default='open')
class RedteamRun(Base):
    __tablename__='redteam_runs'
    id=Column(Integer,primary_key=True); tenant_id=Column(Integer,index=True,nullable=False)
    actor=Column(String(120),nullable=False); results=Column(JSON,nullable=False)
    at=Column(DateTime(timezone=True),default=now)
