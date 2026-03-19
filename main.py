import json
import os
import traceback
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from database import init_db, get_db
from auth import verify_password, get_password_hash, create_access_token, decode_token

app = FastAPI(title="Pigeon Mail")

# Инициализация БД при старте
init_db()

# Подключаем статические файлы
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------- Pydantic модели ----------
class UserRegister(BaseModel):
    phone: str
    password: str
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""

class UserLogin(BaseModel):
    phone: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int

# ---------- REST endpoints ----------
@app.post("/api/register", response_model=TokenResponse)
def register(user: UserRegister):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE phone = %s", (user.phone,))
                existing = cur.fetchone()
                if existing:
                    raise HTTPException(status_code=400, detail="Phone already registered")
                hashed = get_password_hash(user.password)
                cur.execute("""
                    INSERT INTO users (phone, first_name, last_name, hashed_password)
                    VALUES (%s, %s, %s, %s) RETURNING id
                """, (user.phone, user.first_name, user.last_name, hashed))
                user_id = cur.fetchone()["id"]
                conn.commit()
        token = create_access_token({"sub": str(user_id)})
        return TokenResponse(access_token=token, user_id=user_id)
    except HTTPException:
        raise
    except Exception as e:
        print("="*50)
        print("Ошибка в /api/register:")
        traceback.print_exc()
        print("="*50)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/api/login", response_model=TokenResponse)
def login(user: UserLogin):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE phone = %s", (user.phone,))
                db_user = cur.fetchone()
                if not db_user or not verify_password(user.password, db_user["hashed_password"]):
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                user_id = db_user["id"]
        token = create_access_token({"sub": str(user_id)})
        return TokenResponse(access_token=token, user_id=user_id)
    except HTTPException:
        raise
    except Exception as e:
        print("="*50)
        print("Ошибка в /api/login:")
        traceback.print_exc()
        print("="*50)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/me")
def get_current_user(request: Request):
    try:
        token = request.headers.get("authorization", "").replace("Bearer ", "")
        payload = decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(payload["sub"])
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, phone, first_name, last_name FROM users WHERE id = %s",
                    (user_id,)
                )
                user = cur.fetchone()
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                return dict(user)
    except HTTPException:
        raise
    except Exception as e:
        print("="*50)
        print("Ошибка в /api/me:")
        traceback.print_exc()
        print("="*50)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/users")
def get_users(request: Request):
    try:
        token = request.headers.get("authorization", "").replace("Bearer ", "")
        payload = decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        current_user_id = int(payload["sub"])
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, phone, first_name, last_name
                    FROM users
                    WHERE id != %s
                """, (current_user_id,))
                rows = cur.fetchall()
        return [dict(r) for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        print("="*50)
        print("Ошибка в /api/users:")
        traceback.print_exc()
        print("="*50)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/messages/{user_id}")
def get_messages(user_id: int, request: Request):
    try:
        token = request.headers.get("authorization", "").replace("Bearer ", "")
        payload = decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        current_user_id = int(payload["sub"])
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM messages
                    WHERE (sender_id = %s AND recipient_id = %s) OR (sender_id = %s AND recipient_id = %s)
                    ORDER BY created_at ASC
                """, (current_user_id, user_id, user_id, current_user_id))
                rows = cur.fetchall()
        return [dict(r) for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        print("="*50)
        print("Ошибка в /api/messages:")
        traceback.print_exc()
        print("="*50)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ---------- WebSocket менеджер ----------
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)

    async def broadcast(self, message: dict):
        for connection in self.active_connections.values():
            await connection.send_json(message)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_text()
        token_data = json.loads(data)
        token = token_data.get("token")
        payload = decode_token(token)
        if not payload:
            await websocket.close(code=1008, reason="Invalid token")
            return
        user_id = int(payload["sub"])
    except Exception as e:
        print(f"WebSocket auth error: {e}")
        traceback.print_exc()
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, user_id)

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            recipient_id = message.get("recipient_id")
            content = message.get("content")
            if not recipient_id or not content:
                continue

            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO messages (sender_id, recipient_id, content)
                        VALUES (%s, %s, %s) RETURNING id, created_at
                    """, (user_id, recipient_id, content))
                    inserted = cur.fetchone()
                    msg_id = inserted["id"]
                    created_at = inserted["created_at"]
                    conn.commit()

            out_msg = {
                "id": msg_id,
                "sender_id": user_id,
                "recipient_id": recipient_id,
                "content": content,
                "created_at": created_at.isoformat() if created_at else None
            }
            await manager.send_personal_message(out_msg, recipient_id)
            await manager.send_personal_message(out_msg, user_id)

    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        traceback.print_exc()
        manager.disconnect(user_id)
