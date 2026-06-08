import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()
scan_queues: dict[int, asyncio.Queue] = {}


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: int):
    await websocket.accept()

    queue = scan_queues.get(scan_id)
    if not queue:
        await websocket.send_json({"type": "error", "message": "Scan not found or already completed"})
        await websocket.close()
        return

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=120)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            await websocket.send_json(event)

            if event.get("type") in ("scan_done", "scan_error"):
                scan_queues.pop(scan_id, None)
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
