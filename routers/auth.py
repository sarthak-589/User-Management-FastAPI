from datetime import  timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from database import SessionLocal
from sqlalchemy.orm import Session
from models import Users
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import ExpiredSignatureError
from jose import JWTError
from fastapi.security import HTTPBearer

basic_token_auth = HTTPBearer()

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = 'c3c287ea8285280cd50252196d4b5eeed07805bc02cee7dff2f071d69498316e'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 5
REFRESH_SECRET_KEY = '77c02fe8a5f7aaa34848522021f2aae133df62efeb6671314f0d7b84843637a3'
REFRESH_ALGORITHM = 'HS256'
REFRESH_TOKEN_EXPIRE_MINUTES = 10

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenWithRefresh(Token):
    refresh_token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LoginRequest(BaseModel):
    username: str
    password: str



def get_db():
    db = SessionLocal()
    try:
        yield db    # When yield db is called, it provides the db session to the caller. The  function then pauses, maintaining its state until the caller is done using the db.
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]   
''' Depends(get_db):- tell the framework to use the get_db function to resolve this dependency.
    `Depends` is a function provided by fast api to declare dependencies in request handling.
    
    Purpose: The `db_dependecy` variable encapsulates the session creation and management logic,
    making it easy to inject a database session into route handlers or other parts of the application.'''

def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expires = datetime.utcnow() + expires_delta
    to_encode.update({'exp': expires})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expires = datetime.utcnow() + expires_delta
    to_encode.update({'exp': expires})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=REFRESH_ALGORITHM)


async def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(basic_token_auth)]):
    token = credentials.credentials           # This line extracts the token from the provided credentials.
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.', headers={"WWW-Authenticate": "Bearer"})
        return {'username': username, 'id': user_id}
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Token has expired', headers={"WWW-Authenticate": "Bearer"})
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.', headers={"WWW-Authenticate": "Bearer"})

'''Asynchronous APIs enable simultaneous handling of multiple requests for effective communication between services.'''

@router.post("/token", response_model=TokenWithRefresh)
async def login_for_access_token(db: db_dependency, login_request: LoginRequest):
    user = authenticate_user(login_request.username, login_request.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.', headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token({'sub': user.username, 'id': user.id}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_refresh_token({'sub': user.username, 'id': user.id}, timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}



@router.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_token_request: RefreshTokenRequest):
    try:
        payload = jwt.decode(refresh_token_request.refresh_token, REFRESH_SECRET_KEY, algorithms=[REFRESH_ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate refresh token.')
        new_access_token = create_access_token({'sub': username, 'id': user_id}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {'access_token': new_access_token, 'token_type': 'bearer'}
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token has expired.')
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate refresh token.')