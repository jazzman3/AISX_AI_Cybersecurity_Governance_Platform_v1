"""AISX unified defensive AI-security governance platform."""
import hashlib, hmac, json, os, secrets, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from .db import Base, engine, SessionLocal, Tenant, User, Event, ToolRequest, Asset, Alert, RedteamRun
from .security import scan_text, policy_for_tool, assess_asset, triage_alert, redteam_suite

ROOT=Path(__file__).resolve().parent.parent
SECRET=os.getenv('SESSION_SECRET','')
COOKIE_SECURE=os.getenv('COOKIE_SECURE','true').lower()=='true'
SESSION_TTL=3600
PH=PasswordHasher()
app=FastAPI(title='AISX AI Cybersecurity & Governance',version='1.0.0', docs_url=None, redoc_url=None)
app.mount('/static',StaticFiles(directory=str(ROOT/'static')),name='static')
_login_attempts={}

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()

def serializer():
    if len(SECRET)<32: raise RuntimeError('SESSION_SECRET must contain 32+ characters')
    return URLSafeTimedSerializer(SECRET,salt='aisx-auth-v1')

def audit(db:Session, tenant:int, actor:str, category:str, action:str, result:str, detail:dict):
    # Hash linkage is evidence of accidental changes, not independent immutable storage.
    last=db.execute(select(Event).where(Event.tenant_id==tenant).order_by(Event.id.desc())).scalars().first()
    prev=last.entry_hash if last else '0'*64
    sanitized=json.dumps(detail,sort_keys=True,default=str)
    digest=hashlib.sha256(f'{prev}|{tenant}|{actor}|{category}|{action}|{result}|{sanitized}'.encode()).hexdigest()
    entry=Event(tenant_id=tenant,actor=actor,category=category,action=action,result=result,
                detail=detail,prev_hash=prev,entry_hash=digest)
    db.add(entry); db.commit(); return entry

@app.on_event('startup')
def startup():
    serializer()
    Base.metadata.create_all(engine) # replace with Alembic migrations for managed production
    admin=os.getenv('BOOTSTRAP_ADMIN','')
    password=os.getenv('BOOTSTRAP_PASSWORD','')
    if admin or password:
        if not admin or len(password)<16: raise RuntimeError('BOOTSTRAP_ADMIN and a 16+ character BOOTSTRAP_PASSWORD required together')
        with SessionLocal() as db:
            tenant=db.execute(select(Tenant).where(Tenant.name=='AISX Demo')).scalar_one_or_none()
            if not tenant: tenant=Tenant(name='AISX Demo'); db.add(tenant); db.flush()
            if not db.execute(select(User).where(User.tenant_id==tenant.id, User.username==admin)).scalar_one_or_none():
                db.add(User(tenant_id=tenant.id,username=admin,password_hash=PH.hash(password),role='admin'))
            db.commit()

@app.middleware('http')
async def security_headers(request:Request, call_next):
    if request.headers.get('content-length') and int(request.headers['content-length'])>64_000:
        return JSONResponse({'detail':'Payload too large'},status_code=413)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
        'Referrer-Policy':'no-referrer','Cache-Control':'no-store',
        'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
    return response

def current(request:Request, db:Session=Depends(get_db)) -> User:
    token=request.cookies.get('aisx_session','')
    try: data=serializer().loads(token,max_age=SESSION_TTL)
    except (BadSignature,SignatureExpired): raise HTTPException(401,'Authentication required')
    user=db.get(User,data.get('uid'))
    if not user or not user.active or user.tenant_id!=data.get('tenant'):
        raise HTTPException(401,'Invalid session')
    if request.method not in ('GET','HEAD','OPTIONS'):
        csrf=request.headers.get('x-csrf-token','')
        expected=hmac.new(SECRET.encode(),token.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(csrf,expected): raise HTTPException(403,'CSRF validation failed')
    return user

def roles(*allowed):
    def check(user:User=Depends(current)):
        if user.role not in allowed: raise HTTPException(403,'Insufficient role')
        return user
    return check

class Credentials(BaseModel):
    username:str=Field(min_length=1,max_length=120)
    password:str=Field(min_length=1,max_length=500)

@app.post('/api/v1/login')
def login(body:Credentials, request:Request, response:Response, db:Session=Depends(get_db)):
    ip=request.client.host if request.client else 'unknown'
    recent=[t for t in _login_attempts.get(ip,[]) if time.monotonic()-t<300]
    if len(recent)>=8: raise HTTPException(429,'Too many attempts; try later')
    recent.append(time.monotonic()); _login_attempts[ip]=recent
    user=db.execute(select(User).where(User.username==body.username,User.active.is_(True))).scalars().first()
    ok=False
    if user:
        try: ok=PH.verify(user.password_hash,body.password)
        except (VerifyMismatchError,VerificationError): pass
    if not ok: raise HTTPException(401,'Invalid credentials')
    _login_attempts.pop(ip,None)
    token=serializer().dumps({'uid':user.id,'tenant':user.tenant_id})
    response.set_cookie('aisx_session',token, max_age=SESSION_TTL,httponly=True, secure=COOKIE_SECURE,samesite='strict',path='/')
    return {'username':user.username,'role':user.role,
            'csrf_token':hmac.new(SECRET.encode(),token.encode(),hashlib.sha256).hexdigest()}

@app.post('/api/v1/logout')
def logout(response:Response,user:User=Depends(current)):
    response.delete_cookie('aisx_session',path='/'); return {'ok':True}

@app.get('/api/v1/me')
def me(request:Request,user:User=Depends(current)):
    token=request.cookies.get('aisx_session','')
    return {'username':user.username,'role':user.role,'tenant_id':user.tenant_id,
      'csrf_token':hmac.new(SECRET.encode(),token.encode(),hashlib.sha256).hexdigest()}

class UserCreate(BaseModel):
    username:str=Field(min_length=3,max_length=120,pattern=r'^[a-zA-Z0-9_.-]+$')
    password:str=Field(min_length=16,max_length=200)
    role:Literal['admin','analyst','approver','viewer']

@app.post('/api/v1/users',status_code=201)
def add_user(body:UserCreate,user:User=Depends(roles('admin')),db:Session=Depends(get_db)):
    exists=db.execute(select(User).where(User.tenant_id==user.tenant_id,User.username==body.username)).scalar_one_or_none()
    if exists: raise HTTPException(409,'User already exists')
    record=User(username=body.username,tenant_id=user.tenant_id,role=body.role,password_hash=PH.hash(body.password))
    db.add(record); db.commit()
    audit(db,user.tenant_id,user.username,'identity','create_user','created',{'username':body.username,'role':body.role})
    return {'id':record.id,'username':record.username,'role':record.role}

@app.get('/api/v1/users')
def users(user:User=Depends(roles('admin')),db:Session=Depends(get_db)):
    return [{'id':r.id,'username':r.username,'role':r.role} for r in db.execute(select(User).where(User.tenant_id==user.tenant_id)).scalars()]

class ScanInput(BaseModel):
    text:str=Field(min_length=1,max_length=12000)
    mode:Literal['input','output']='input'

@app.post('/api/v1/gateway/scan')
def gateway(body:ScanInput,user:User=Depends(roles('admin','analyst')),db:Session=Depends(get_db)):
    result=scan_text(body.text,body.mode)
    # raw content intentionally never stored in audit log
    audit(db,user.tenant_id,user.username,'gateway','scan',result['decision'],
          {'rules':[x['rule'] for x in result['rules']], 'sensitive_types':result['sensitive_types'], 'text_length':len(body.text)})
    return result

class ToolInput(BaseModel):
    tool:str=Field(min_length=3,max_length=90,pattern=r'^[a-z_]+$')
    purpose:str=Field(min_length=5,max_length=400)

@app.post('/api/v1/agents/requests',status_code=201)
def request_tool(body:ToolInput,user:User=Depends(roles('admin','analyst')),db:Session=Depends(get_db)):
    decision=policy_for_tool(body.tool)
    status={'allow':'authorized','approve':'pending','deny':'denied'}[decision]
    record=ToolRequest(tenant_id=user.tenant_id,requester_id=user.id,tool=body.tool,purpose=body.purpose,status=status)
    db.add(record);db.commit();db.refresh(record)
    audit(db,user.tenant_id,user.username,'agent','request_tool',status,{'id':record.id,'tool':body.tool})
    return {'id':record.id,'tool':record.tool,'status':status,'policy':decision,
            'note':'Approval does not execute an external tool.'}

@app.get('/api/v1/agents/requests')
def tool_requests(user:User=Depends(current),db:Session=Depends(get_db)):
    records=db.execute(select(ToolRequest).where(ToolRequest.tenant_id==user.tenant_id).order_by(ToolRequest.id.desc()).limit(100)).scalars()
    return [{'id':r.id,'tool':r.tool,'status':r.status,'requester_id':r.requester_id,'approver_id':r.approver_id} for r in records]

class DecisionInput(BaseModel):
    decision:Literal['approved','rejected']

@app.post('/api/v1/agents/requests/{request_id}/decision')
def decide_tool(request_id:int,body:DecisionInput,user:User=Depends(roles('approver','admin')),db:Session=Depends(get_db)):
    record=db.execute(select(ToolRequest).where(ToolRequest.id==request_id,ToolRequest.tenant_id==user.tenant_id).with_for_update()).scalar_one_or_none()
    if not record: raise HTTPException(404,'Request not found')
    if record.status!='pending': raise HTTPException(409,'Request not pending')
    if record.requester_id==user.id: raise HTTPException(403,'Two-person approval is required')
    record.status=body.decision; record.approver_id=user.id;db.commit()
    audit(db,user.tenant_id,user.username,'agent','approve_tool',body.decision,{'id':request_id,'tool':record.tool})
    return {'id':record.id,'status':record.status,'executed':False}

class AssetInput(BaseModel):
    name:str=Field(min_length=2,max_length=160)
    owner:str=Field(min_length=2,max_length=120)
    public_exposure:bool=False
    sensitive_data:bool=False
    has_dlp:bool=False
    agent_tools:bool=False
    approval_gates:bool=False
    monitoring:bool=False

@app.post('/api/v1/posture/assets',status_code=201)
def add_asset(body:AssetInput,user:User=Depends(roles('admin','analyst')),db:Session=Depends(get_db)):
    cfg=body.model_dump();risk=assess_asset(cfg)
    record=Asset(tenant_id=user.tenant_id,name=body.name,owner=body.owner,config=cfg,assessment=risk)
    db.add(record);db.commit();db.refresh(record)
    audit(db,user.tenant_id,user.username,'posture','assess_asset',risk['status'],{'id':record.id,'risk_score':risk['risk_score']})
    return {'id':record.id,'name':record.name,'assessment':risk}

@app.get('/api/v1/posture/assets')
def assets(user:User=Depends(current),db:Session=Depends(get_db)):
    return [{'id':r.id,'name':r.name,'owner':r.owner,'assessment':r.assessment} for r in db.execute(select(Asset).where(Asset.tenant_id==user.tenant_id).order_by(Asset.id.desc()).limit(100)).scalars()]

class AlertInput(BaseModel):
    title:str=Field(min_length=3,max_length=160)
    privileged:bool=False
    external_destination:bool=False
    sensitive_asset:bool=False
    repeat_count:int=Field(default=1,ge=1,le=100000)

@app.post('/api/v1/soc/alerts',status_code=201)
def add_alert(body:AlertInput,user:User=Depends(roles('admin','analyst')),db:Session=Depends(get_db)):
    signal=body.model_dump(); triage=triage_alert(signal)
    record=Alert(tenant_id=user.tenant_id,title=body.title,signal=signal,triage=triage)
    db.add(record);db.commit();db.refresh(record)
    audit(db,user.tenant_id,user.username,'soc','triage_alert',triage['priority'],{'id':record.id,'score':triage['score']})
    return {'id':record.id,'title':record.title,'triage':triage}

@app.get('/api/v1/soc/alerts')
def alerts(user:User=Depends(current),db:Session=Depends(get_db)):
    return [{'id':r.id,'title':r.title,'triage':r.triage,'status':r.status} for r in db.execute(select(Alert).where(Alert.tenant_id==user.tenant_id).order_by(Alert.id.desc()).limit(100)).scalars()]

@app.post('/api/v1/redteam/runs',status_code=201)
def run_redteam(user:User=Depends(roles('admin','analyst')),db:Session=Depends(get_db)):
    results=redteam_suite();run=RedteamRun(tenant_id=user.tenant_id,actor=user.username,results=results)
    db.add(run);db.commit();db.refresh(run)
    audit(db,user.tenant_id,user.username,'redteam','evaluate','complete',{'id':run.id,'passed':sum(x['passed'] for x in results),'total':len(results)})
    return {'id':run.id,'passed':sum(x['passed'] for x in results),'total':len(results),'results':results}

@app.get('/api/v1/redteam/runs')
def redteam_runs(user:User=Depends(current),db:Session=Depends(get_db)):
    return [{'id':r.id,'passed':sum(x['passed'] for x in r.results),'total':len(r.results)} for r in db.execute(select(RedteamRun).where(RedteamRun.tenant_id==user.tenant_id).order_by(RedteamRun.id.desc()).limit(30)).scalars()]

@app.get('/api/v1/audit')
def events(user:User=Depends(roles('admin','analyst','approver')),db:Session=Depends(get_db)):
    return [{'id':r.id,'category':r.category,'action':r.action,'actor':r.actor,'result':r.result,'detail':r.detail,'timestamp':str(r.at)} for r in db.execute(select(Event).where(Event.tenant_id==user.tenant_id).order_by(Event.id.desc()).limit(100)).scalars()]

@app.get('/api/v1/summary')
def summary(user:User=Depends(current),db:Session=Depends(get_db)):
    tid=user.tenant_id
    def count(model): return db.scalar(select(func.count()).select_from(model).where(model.tenant_id==tid))
    return {'assets':count(Asset),'alerts':count(Alert),'tool_requests':count(ToolRequest),
            'redteam_runs':count(RedteamRun),'audit_events':count(Event),'tenant':tid}

@app.get('/health/live')
def live(): return {'status':'ok'}
@app.get('/health/ready')
def ready(db:Session=Depends(get_db)):
    db.execute(select(func.count()).select_from(Tenant)).scalar()
    return {'status':'ready'}
@app.get('/')
def index(): return FileResponse(ROOT/'static'/'index.html')
