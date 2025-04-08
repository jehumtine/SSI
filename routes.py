from fastapi import APIRouter
from fastapi.responses import JSONResponse
from models import IdentityPackage, UserPackage
import services

router = APIRouter()

@router.post("/create-identity")
async def create_identity(identity: IdentityPackage):
    """
    :param identity:
    :return: user_package
    Endpoint to create identity
    """
    try:
        user_package = await services.create_identity(identity)
        return user_package
    except Exception as e:
        return JSONResponse({"error": str(e)})

@router.post("/verify-identity")
async def verify_identity(user_package: UserPackage):
    """
    :param user_package:
    :return: True or False depending on whether identity was verified
    """
    try:
        response = await services.verify_identity(user_package)
        return JSONResponse({"response": response})
    except Exception as e:
        return JSONResponse({"error": str(e)})


