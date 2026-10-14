"""Dependency-light password hashing and signed bearer tokens.

The token format is compact JSON + HMAC-SHA256, with strict expiry checks.
Use a unique random JWT_SECRET in any shared or production deployment.
"""
import base64, hashlib, hmac, json, secrets, time
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db import get_db
from app.models import User

bearer = HTTPBearer(auto_error=False)
ITERATIONS = 390_000

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
def hash_password(password: str) -> str:
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,ITERATIONS,dklen=32)
    return f"pbkdf2_sha256${ITERATIONS}${_b64(salt)}${_b64(digest)}"
def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt, expected=encoded.split("$",3)
        if scheme!="pbkdf2_sha256": return False
        actual=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),_unb64(salt),int(iterations),dklen=32)
        return hmac.compare_digest(actual,_unb64(expected))
    except (ValueError,TypeError): return False
def create_access_token(user: User) -> str:
    now=int(time.time())
    header={"alg":"HS256","typ":"JWT"}; payload={"sub":str(user.id),"iat":now,"exp":now+max(1,int(settings.access_token_minutes))*60}
    signing=f"{_b64(json.dumps(header,separators=(',',':')).encode())}.{_b64(json.dumps(payload,separators=(',',':')).encode())}"
    sig=hmac.new(settings.jwt_secret.encode("utf-8"),signing.encode("ascii"),hashlib.sha256).digest()
    return signing+"."+_b64(sig)
def get_current_user(credentials: HTTPAuthorizationCredentials|None=Depends(bearer), db: Session=Depends(get_db)) -> User:
    exc=HTTPException(status_code=401,detail="Authentication required or token expired",headers={"WWW-Authenticate":"Bearer"})
    if not credentials: raise exc
    try:
        header,body,signature=credentials.credentials.split(".",2); signing=f"{header}.{body}"
        expected=hmac.new(settings.jwt_secret.encode("utf-8"),signing.encode("ascii"),hashlib.sha256).digest()
        if not hmac.compare_digest(expected,_unb64(signature)): raise exc
        h=json.loads(_unb64(header)); payload=json.loads(_unb64(body))
        if h.get("alg")!="HS256" or int(payload.get("exp",0))<=int(time.time()): raise exc
        user=db.get(User,int(payload.get("sub","")))
    except HTTPException: raise
    except (ValueError,TypeError,KeyError,UnicodeDecodeError,json.JSONDecodeError): raise exc
    if not user or not user.active: raise exc
    return user
def require_roles(*allowed_roles: str):
    def dependency(current_user: User=Depends(get_current_user)):
        if current_user.role not in allowed_roles: raise HTTPException(status_code=403,detail="Your account role is not authorized for this action")
        return current_user
    return dependency
