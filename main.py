from fastapi import FastAPI

from app import auth
from app import device
from app import models
from app.database import engine


app = FastAPI(
    title="	ArmPromConsulting",
    description="Device activation API",
    version="0.1",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1}
)

# app = FastAPI(openapi_url=None)

app.include_router(auth.router)
app.include_router(device.router)


# Create tables
models.Base.metadata.create_all(bind=engine)

