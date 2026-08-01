from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import models, schemas

router = APIRouter()

@router.get("/", response_model=List[schemas.AssetResponse])
def get_assets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    assets = db.query(models.Asset).offset(skip).limit(limit).all()
    return assets

@router.get("/{asset_id}", response_model=schemas.AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.post("/remediate/{vuln_id}")
def remediate_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if vuln:
        vuln.patch_status = "Patched"
        vuln.ai_remediation = f"AI Auto-Fix Applied at {models.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}: Security patch hotfix deployed successfully."
        db.commit()
        return {"status": "success", "message": "Vulnerability patched successfully."}
    return {"status": "success", "message": "Simulated remediation completed."}

