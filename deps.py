from jose import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from utils import JWT_SECRET_KEY,ALGORITHM
def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.JWTError:
        return None


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    user = decode_token(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


ACCESS_TOKEN_EXPIRE_MINUTES = 30
TOKEN_URL = "/api/auth/token"
TOKEN_MANAGER = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)