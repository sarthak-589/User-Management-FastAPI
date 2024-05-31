from email.policy import HTTP
import bcrypt
from fastapi  import APIRouter, Depends, HTTPException, status, Path
from typing import Annotated, List, Optional
from sqlalchemy.orm import Session
from models import Users
from database import SessionLocal
from pydantic import BaseModel, Field, EmailStr
from routers import auth
from .auth import get_current_user
from passlib.context import CryptContext


router = APIRouter(
    prefix='/user',
    tags=['user']
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)
    

class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr  # Email validation
    first_name: str
    last_name: str
    phone_number: str = Field(..., pattern=r'^\+?1?\d{9,15}$')  # Phone number validation
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    phone_number: str


class UserUpdateRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None   # Email validation
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = Field(None, pattern=r'^\+?1?\d{9,15}$')    # Phone number validation
    current_password: Optional[str] = None
    new_password: Optional[str] = None





@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = Users(
        email=create_user_request.email,
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        phone_number=create_user_request.phone_number,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )
    db.add(create_user_model)
    db.commit()


@router.get('/', response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_current_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    user_data = db.query(Users).filter(Users.id == user.get('id')).first()
    if user_data is None:
        raise HTTPException(status_code=404, detail='User not found')
    
    # Ensure that the username is a string
    if not isinstance(user_data.username, str):
        raise HTTPException(status_code=500, detail='Invalid data type for username')


    return UserResponse(
        id=user_data.id,
        username=user_data.username,
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        phone_number=user_data.phone_number
    )



# @router.get('/', response_model=List[UserResponse], status_code=status.HTTP_200_OK)
# async def get_all_users(user: user_dependency, db: db_dependency):
#     if user is None:
#         raise HTTPException(status_code=401, detail='Authentication Failed')
#     users = db.query(Users).all()
#     if not users:
#         raise HTTPException(status_code=404, detail='No users found')
    
#     users_response = []
#     for user_data in users:
#         # Ensure that the username is a string
#         if not isinstance(user_data.username, str):
#             raise HTTPException(status_code=500, detail='Invalid data type for username')
        
#         users_response.append(UserResponse(
#             id=user_data.id,
#             username=user_data.username,
#             email=user_data.email,
#             first_name=user_data.first_name,
#             last_name=user_data.last_name,
#             phone_number=user_data.phone_number
#         ))
    
#     return users_response



@router.put('/', response_model=UserResponse, status_code=status.HTTP_200_OK)
async def update_user(user: user_dependency, db: db_dependency, user_update: UserUpdateRequest):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    user_data = db.query(Users).filter(Users.id == user.get('id')).first()
    if user_data is None:
        raise HTTPException(status_code=404, detail='User Not Found')
    
    if user_update.username:
        user_data.username = user_update.username
    if user_update.email:
        user_data.email = user_update.email
    if user_update.first_name:
        user_data.first_name = user_update.first_name
    if user_update.last_name:
        user_data.last_name = user_update.last_name
    if user_update.phone_number:
        user_data.phone_number = user_update.phone_number
    if user_update.current_password and user_update.new_password:
        if not bcrypt_context.verify(user_update.current_password, user_data.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        user_data.hashed_password = bcrypt_context.hash(user_update.new_password)

    db.commit()
    db.refresh(user_data)

    return UserResponse(
        id=user_data.id,
        username=user_data.username,
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        phone_number=user_data.phone_number
    )


# @router.delete('/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
# async def delete_user(user_id: int, user: user_dependency, db: db_dependency):
#     if user is None:
#         raise HTTPException(status_code=401, detail='Authentication Failed')
#     user_data = db.query(Users).filter(Users.id == user.get('id')).first()
#     if user_data is None:
#         raise HTTPException(status_code=404, detail='User Not Found')
    
#     db.delete(user_data)
#     db.commit()
#     return 



# @router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
# async def change_password(user: user_dependency, db: db_dependency, user_verification: UserVerification):
#     if user is None:
#         raise HTTPException(status_code=401, detail='Authentication Failed')
#     user_model = db.query(Users).filter(Users.id == user.get('id')).first()

#     if not bcrypt_context.verify(user_verification.password, user_model.hashed_password):
#         raise HTTPException(status_code=401, detail='Error on Password change')
    
#     user_model.hashed_password = bcrypt_context.hash(user_verification.new_password)
#     db.add(user_model)
#     db.commit()