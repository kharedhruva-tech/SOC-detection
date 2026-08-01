from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import Asset, Vulnerability
from app.models.schemas import AssetResponse, VulnerabilityResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/assets", tags=["Asset & Vulnerability Management"])

@router.get("/", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(Asset).all()

@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.get("/vulnerabilities/", response_model=List[VulnerabilityResponse])
def get_all_vulnerabilities(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(Vulnerability).all()

@router.post("/remediate/{vuln_id}")
def get_vulnerability_ai_remediation(vuln_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    # Generate custom AI recommendations
    ai_remed = (
        f"### AI Patch Strategy for {vuln.cve_id} ({vuln.title})\n\n"
        "**Technical Impact Summary**:\n"
        f"This vulnerability exposes the target host `{vuln.asset.name}` to potential remote exploit vectors. "
        f"With a CVSS score of `{vuln.cvss_score}`, immediate patching is highly advised.\n\n"
        "**Step-by-step Action Plan**:\n"
        "1. **Audit Dependency**: Verify if the vulnerable software library or service is actively executing.\n"
        "2. **Patch Command**:\n"
    )
    if "linux" in vuln.asset.os.lower():
        ai_remed += "   ```bash\n   sudo apt-get update && sudo apt-get install --only-upgrade " + vuln.title.split()[0].lower() + "\n   ```\n"
    else:
        ai_remed += "   Apply KB security patches via Windows Update Manager (WSUS) and reboot target endpoint.\n"
        
    ai_remed += (
        "3. **Alternative Mitigation**: If instant patching is not viable, isolate the port or disable remote services "
        "at the local Host EDR firewall to mitigate remote execution risks.\n"
        "4. **Re-scan**: Trigger the vulnerability scanner to re-index the patch state after remediation."
    )
    
    # Save the AI remediation to the DB record
    vuln.ai_remediation = ai_remed
    db.commit()
    db.refresh(vuln)
    
    return {"ai_remediation": ai_remed}
