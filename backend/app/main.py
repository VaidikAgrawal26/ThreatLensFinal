from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db import Base, engine, SessionLocal
from app import models
from app.routes import scans, analytics, yara, model, auth, admin, incidents, research
from app.core.security import hash_password
Path("data").mkdir(exist_ok=True)
Base.metadata.create_all(bind=engine)
if settings.bootstrap_admin_email and settings.bootstrap_admin_password and (settings.jwt_secret == "CHANGE_ME_BEFORE_DEPLOYMENT_TO_A_LONG_RANDOM_SECRET" or len(settings.jwt_secret) < 32):
    raise RuntimeError("Set JWT_SECRET to a unique random value of at least 32 characters before bootstrapping an administrator.")
# Optional one-time administrator bootstrap. Never ship credentials in source control.
if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
    db=SessionLocal()
    try:
        email=settings.bootstrap_admin_email.strip().lower()
        if not db.query(models.User).filter(models.User.email==email).first():
            admin_user=models.User(email=email,password_hash=hash_password(settings.bootstrap_admin_password),full_name="ThreatLens Administrator",role="administrator",active=True)
            db.add(admin_user); db.commit()
    finally: db.close()
app=FastAPI(title=settings.app_name,version="2.0.0",description="Static malware triage and scan analytics. Uploaded files are never executed.")
app.add_middleware(CORSMiddleware,allow_origins=settings.origins,allow_credentials=False,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type"])
for router in (auth.router,admin.router,incidents.router,research.router,scans.router,analytics.router,yara.router,model.router): app.include_router(router)
@app.get("/")
def root(): return {"name":settings.app_name,"docs":"/docs","health":"/health"}
@app.get("/health")
def health(): return {"status":"ok","service":"threatlens-api"}
