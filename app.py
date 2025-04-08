from fastapi import FastAPI
from routes import router as identity_router

app = FastAPI()

app.include_router(identity_router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the future of Digital Identity"}