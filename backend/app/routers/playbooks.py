from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import Playbook, PlaybookRun
from app.models.schemas import PlaybookResponse, PlaybookCreate, PlaybookUpdate, PlaybookRunResponse
from app.routers.auth import get_current_user
from app.services.soar_executor import soar_executor

router = APIRouter(prefix="/playbooks", tags=["SOAR Automation"])

@router.get("/", response_model=List[PlaybookResponse])
def get_playbooks(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(Playbook).all()

@router.post("/", response_model=PlaybookResponse)
def create_playbook(
    playbook_in: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    playbook = Playbook(
        name=playbook_in.name,
        description=playbook_in.description,
        trigger_condition=playbook_in.trigger_condition,
        nodes=playbook_in.nodes,
        edges=playbook_in.edges,
        creator=current_user.username
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook

@router.put("/{playbook_id}", response_model=PlaybookResponse)
def update_playbook(
    playbook_id: int,
    playbook_in: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
        
    if playbook_in.description is not None:
        playbook.description = playbook_in.description
    if playbook_in.is_active is not None:
        playbook.is_active = playbook_in.is_active
    if playbook_in.trigger_condition is not None:
        playbook.trigger_condition = playbook_in.trigger_condition
    if playbook_in.nodes is not None:
        playbook.nodes = playbook_in.nodes
    if playbook_in.edges is not None:
        playbook.edges = playbook_in.edges
    if playbook_in.version is not None:
        playbook.version = playbook_in.version

    db.commit()
    db.refresh(playbook)
    return playbook

@router.post("/run", response_model=PlaybookRunResponse)
def execute_playbook(
    playbook_id: int,
    incident_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    try:
        run = soar_executor.run_playbook(
            db=db,
            playbook_id=playbook_id,
            incident_id=incident_id,
            triggered_by=current_user.username
        )
        return run
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/runs", response_model=List[PlaybookRunResponse])
def get_playbook_runs(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(PlaybookRun).order_by(PlaybookRun.started_at.desc()).all()
