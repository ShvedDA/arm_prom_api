from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from app.database import SessionLocal
from app.models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError

router = APIRouter(
    prefix='/auth',
    tags=['Authentication and Users']
)

SECRET_KEY = '593d92404de37c2a0cc7600e58713cd96b71c453ba2aadb2c2e1e17ed55942ca'
ALGORITHM = 'HS256'
# 7 days life of token
ACCESS_TOKEN_EXPIRE_MINUTES = 7 * 24 * 60

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class CreateUserRequest(BaseModel):
    username: str
    fullname: str
    password: str
    email: str
    admin: bool


class EditUserRequest(BaseModel):
    fullname: str
    password: str
    email: str
    admin: bool


class Token(BaseModel):
    access_token: str
    token_type: str


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user!')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user!')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate user!")
    token = create_access_token(user.username, user.id, timedelta(ACCESS_TOKEN_EXPIRE_MINUTES))

    return {'access_token': token, 'token_type': 'bearer'}


@router.post("/add_user", status_code=status.HTTP_201_CREATED)
async def create_new_user(user: user_dependency, db: db_dependency, create_user_request: CreateUserRequest):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    db_item = db.query(Users).filter(Users.username == user['username']).first()
    if db_item.admin is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user isn\'t admin!')
    db_item = db.query(Users).filter(Users.username == create_user_request.username).first()
    if db_item is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This user have been already registrated!')
    create_user_model = Users(
        username=create_user_request.username,
        fullname=create_user_request.fullname,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        email=create_user_request.email,
        admin=create_user_request.admin
    )
    db.add(create_user_model)
    db.commit()
    return {"New user was added:": create_user_model.username}


@router.patch("/edit_user/{edited_username}", status_code=status.HTTP_202_ACCEPTED)
async def edit_user(user: user_dependency, db: db_dependency, edited_username: str, edit_user_request: EditUserRequest):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    db_item = db.query(Users).filter(Users.username == user['username']).first()
    if db_item.admin is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user isn\'t admin!')
    db_item = db.query(Users).filter(Users.username == edited_username).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No such user in DB!')
    db_item.fullname = edit_user_request.fullname
    db_item.hashed_password = bcrypt_context.hash(edit_user_request.password)
    db_item.email = edit_user_request.email
    db_item.admin = edit_user_request.admin
    db.commit()
    return {"User credentials were updated:": edited_username}


@router.post("/del_user/{deleted_username}", status_code=status.HTTP_202_ACCEPTED)
async def delete_user(user: user_dependency, db: db_dependency, deleted_username: str):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    db_item = db.query(Users).filter(Users.username == user['username']).first()
    if db_item.admin is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user isn\'t admin!')
    if deleted_username in user.values():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user can\'t be deleted!')
    user = db.query(Users).filter(Users.username == deleted_username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail='No such user in DB!')
    db.delete(user)
    db.commit()
    return {"User was deleted:": user.username}


def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


@router.get("/info_user/{username}", status_code=status.HTTP_200_OK)
async def get_info_about_user(user: user_dependency, db: db_dependency, username: str):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    db_item = db.query(Users).filter(Users.username == user['username']).first()
    if db_item.admin is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user isn\'t admin!')
    user = db.query(Users).filter(Users.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No such user in DB!')
    return user
