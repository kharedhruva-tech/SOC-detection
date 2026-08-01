from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.database import get_db
from app.models import models, schemas

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    # Check DB user
    user = db.query(models.User).filter(models.User.username == req.username).first()
    
    # Allow admin / admin or any valid matching credentials
    if req.username == "admin" and req.password == "2006":
        if not user:
            user = models.User(
                username="admin",
                email="admin@aegis-soc.corp",
                hashed_password="2006",
                full_name="System Administrator",
                role="Super Admin"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        return {
            "access_token": f"aegis-token-{user.id}-admin-session",
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
            "full_name": user.full_name or "System Administrator"
        }

    # Allow user / user or any valid matching credentials
    if req.username == "user" and req.password == "user":
        if not user:
            user = models.User(
                username="user",
                email="user@aegis-soc.corp",
                hashed_password="user",
                full_name="Operations Specialist",
                role="SOC User"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        return {
            "access_token": f"aegis-token-{user.id}-user-session",
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
            "full_name": user.full_name or "Operations Specialist"
        }

    if user and user.hashed_password == req.password:
        return {
            "access_token": f"aegis-token-{user.id}-session",
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
            "full_name": user.full_name or user.username
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="INVALID CYBER CREDENTIALS. ACCESS DENIED."
    )
