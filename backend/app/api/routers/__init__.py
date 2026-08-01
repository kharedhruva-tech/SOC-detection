from fastapi import APIRouter
from app.api.routers import incidents, alerts, playbooks, assets, reports, ueba, intel, forensics, auth

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(ueba.router, prefix="/ueba", tags=["ueba"])
api_router.include_router(intel.router, prefix="/intel", tags=["intel"])
api_router.include_router(forensics.router, prefix="/forensics", tags=["forensics"])


