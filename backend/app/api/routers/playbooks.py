from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import models, schemas
from app.services.soar_executor import soar_executor

router = APIRouter()

@router.get("/", response_model=List[schemas.PlaybookResponse])
def get_playbooks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    playbooks = db.query(models.Playbook).offset(skip).limit(limit).all()
    return playbooks

@router.get("/{playbook_id}", response_model=schemas.PlaybookResponse)
def get_playbook(playbook_id: int, db: Session = Depends(get_db)):
    playbook = db.query(models.Playbook).filter(models.Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook

@router.post("/{playbook_id}/execute")
def execute_playbook(playbook_id: int, request: schemas.PlaybookExecuteRequest, db: Session = Depends(get_db)):
    try:
        run = soar_executor.execute_playbook(db, playbook_id, request.incident_id, "API User")
        return {"message": "Playbook execution started", "run_id": run.id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/run")
def run_playbook(playbook_id: int, incident_id: int, db: Session = Depends(get_db)):
    try:
        run = soar_executor.execute_playbook(db, playbook_id, incident_id, "API User")
        return {"message": "Playbook execution started", "run_id": run.id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{playbook_id}", response_model=schemas.PlaybookResponse)
def update_playbook(playbook_id: int, update_data: schemas.PlaybookUpdate, db: Session = Depends(get_db)):
    playbook = db.query(models.Playbook).filter(models.Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    for key, val in update_data.model_dump(exclude_unset=True).items():
        setattr(playbook, key, val)

    db.commit()
    db.refresh(playbook)
    return playbook

