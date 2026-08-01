import sys
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Allow running this file directly (for example: python backend/app/main.py)
BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.database import engine, Base
from app.api.routers import api_router
from app.services.log_generator import log_generator
from app.database_seed import seed_database
from app.ws_manager import ws_manager

# Create database tables
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    print("Starting up SOC Platform Backend...")
    try:
        # Capture the running event loop for threadsafe broadcasts
        ws_manager.loop = asyncio.get_running_loop()
    except Exception as e:
        print(f"Error capturing event loop: {e}")
        
    try:
        seed_database()
        print("Database initial sample records verified/seeded successfully.")
    except Exception as e:
        print(f"Database seed notice: {e}")
    log_generator.start()
    yield
    # Shutdown logic
    print("Shutting down SOC Platform Backend...")
    log_generator.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS – allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {"message": "Welcome to the AI-Integrated SOC Platform API"}


# ──────────────────────────────────────────────
# WebSocket endpoint for live alert streaming
# ──────────────────────────────────────────────
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    print(f"[WS] Client connected. Total: {len(ws_manager.active_connections)}")
    try:
        while True:
            # Keep connection alive; also accept any client messages (e.g. pings)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Echo pings back as pong
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send server-side keepalive ping
                try:
                    await websocket.send_text('{"type":"ping"}')
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_manager.disconnect(websocket)
        print(f"[WS] Client disconnected. Total: {len(ws_manager.active_connections)}")
