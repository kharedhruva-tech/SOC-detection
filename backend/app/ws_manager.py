"""
WebSocket manager for broadcasting real-time alerts to connected dashboard clients.
"""
import asyncio
import json
from typing import List
from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages to all."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send a JSON message to every connected client."""
        payload = json.dumps(message)
        stale: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)
        # Clean up broken connections
        for conn in stale:
            self.disconnect(conn)

    async def send_personal(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_text(json.dumps(message))
        except Exception:
            self.disconnect(websocket)

    def sync_broadcast(self, message: dict):
        """Thread-safe synchronous broadcast."""
        if not hasattr(self, "loop"):
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)



# Global singleton – imported by main.py and siem_engine
ws_manager = ConnectionManager()
