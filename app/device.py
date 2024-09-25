from datetime import datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from app.database import SessionLocal
from app.auth import user_dependency
from app.models import Devices, Users


router = APIRouter(
    prefix='/device',
    tags=['Device']
)


class DeviceRegistrationRequest(BaseModel):
    type: str
    uid: str
    description: str


class DeviceEditRequest(BaseModel):
    type: str
    description: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_auth(user):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')


def check_admin(user, db):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    db_item = db.query(Users).filter(Users.username == user['username']).first()
    if db_item.admin is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Current user isn\'t admin!')



db_dependency = Annotated[Session, Depends(get_db)]


@router.post("/add", status_code=status.HTTP_201_CREATED)
async def registrate_new_device(user: user_dependency, db: db_dependency, registrate_device: DeviceRegistrationRequest):
    await check_auth(user)
    db_item = db.query(Devices).filter(Devices.uid == registrate_device.uid).first()
    if db_item is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This UID have been already registrated!')
    create_device_model = Devices(
        type=registrate_device.type,
        uid=registrate_device.uid,
        activated=False,
        description=registrate_device.description,
        user=user['username']
    )
    db.add(create_device_model)
    db.commit()
    return {"New device was added:": create_device_model.uid}


@router.patch("/activate/{uid}", status_code=status.HTTP_202_ACCEPTED)
async def activate_device(user: user_dependency, db: db_dependency, uid: str):
    await check_auth(user)
    db_item = db.query(Devices).filter(Devices.uid == uid).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No such device in DB!')
    db_item.activated = True
    db_item.date_of_activation = datetime.today().strftime('%d-%m-%Y')
    db_item.user = user['username']
    db.commit()
    return {"Device was activated:": uid}


@router.get("/check/{uid}", status_code=status.HTTP_200_OK)
async def check_device_activation(user: user_dependency, db: db_dependency, uid: str):
    check_auth(user)
    db_item = db.query(Devices).filter(Devices.uid == uid).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No such device in DB!')
    return {"Device": uid, "activation is": db_item.activated}


@router.patch("/edit/{edited_uid}", status_code=status.HTTP_202_ACCEPTED)
async def edit_device(user: user_dependency, db: db_dependency, edited_uid: str, edit_device: DeviceEditRequest):
    check_admin(user, db)
    db_item = db.query(Devices).filter(Devices.uid == edited_uid).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No such device in DB!')
    db_item.type = edit_device.type
    db_item.description = edit_device.description
    db_item.user = user['username']
    db.commit()
    return {"Device info was updated:": edited_uid}


@router.post("/edit/{deleted_uid}", status_code=status.HTTP_202_ACCEPTED)
async def delete_device(user: user_dependency, db: db_dependency, deleted_uid: str):
    check_admin(user, db)
    db_item = db.query(Devices).filter(Devices.uid == deleted_uid).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail='No such device in DB!')
    db.delete(db_item)
    db.commit()
    return {"Device was deleted": deleted_uid}


@router.get("/info_device/{uid}", status_code=status.HTTP_200_OK)
async def get_info_about_device(user: user_dependency, db: db_dependency, uid: str):
    check_admin(user, db)
    db_item = db.query(Devices).filter(Devices.uid == uid).first()
    if db_item is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail='No such device in DB!')
    return db_item

