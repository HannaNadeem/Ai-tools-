# ==============================================================================
# File: main_server.py
# Version: 6.2 (Stable & Corrected)
# ==============================================================================
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Header, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from typing import List, Dict, Optional
import aiosqlite
from pathlib import Path
import datetime
import httpx
import logging
import secrets
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Configuration Management for Main Server ---
class Settings(BaseSettings):
    APP_NAME: str = "Fleet Command"
    DATABASE_URL: str = "sqlite+aiosqlite:///./servers_fleet.v6.db"
    MASTER_REGISTRATION_KEY: str = "REPLACE_THIS_WITH_A_SECURE_MASTER_KEY"
    JWT_SECRET_KEY: str = "REPLACE_THIS_WITH_A_32_BYTE_RANDOM_STRING"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    FIRST_ADMIN_USER: str = "admin"
    FIRST_ADMIN_PASSWORD: str = "changeme"
    
    class Config:
        env_file = ".env"

settings = Settings()
DB_PATH = Path(settings.DATABASE_URL.split("///")[-1])

# --- Security Utilities ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    expire_time = datetime.timedelta(minutes=expires_delta) if expires_delta else datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.datetime.utcnow() + expire_time
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

# --- Pydantic Models ---
class User(BaseModel):
    username: str
class UserInDB(User):
    hashed_password: str
class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    username: Optional[str] = None
class ServerAgentInfo(BaseModel):
    hostname: str; ip_address: str; port: int; os_info: str; group: str = Field(default="default")
class AgentRegistrationResponse(BaseModel):
    server_id: str; api_key: str; message: str
class ServerStatusUpdate(BaseModel):
    cpu_usage: float; memory_usage: float; disk_usage: float; uptime: str
class ServerRecord(ServerAgentInfo):
    server_id: str; status: ServerStatusUpdate; last_seen: datetime.datetime; api_key: Optional[str] = None
class CommandRequest(BaseModel):
    command: str = Field(..., example="df -h")
class CommandResponse(BaseModel):
    server_id: str; command: str; stdout: Optional[str] = None; stderr: Optional[str] = None; error: Optional[str] = None

# --- Database & User Auth ---
async def get_user(db: aiosqlite.Connection, username: str) -> Optional[UserInDB]:
    cursor = await db.execute("SELECT username, hashed_password FROM users WHERE username = ?", (username,))
    user_record = await cursor.fetchone()
    return UserInDB(**user_record) if user_record else None

async def get_current_user_from_cookie(request: Request) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token: return None
    if token.startswith("Bearer "): token = token.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None: return None
    except JWTError: return None
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        user = await get_user(db, username=username)
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user_from_cookie)):
    if not current_user: raise HTTPException(status_code=307, headers={"Location": "/login"})
    return current_user

def verify_master_key(x_master_key: str = Header(...)):
    if not secrets.compare_digest(x_master_key, settings.MASTER_REGISTRATION_KEY):
        raise HTTPException(status_code=401, detail="Invalid Master Registration Key")

async def get_agent_from_db(server_id: str, db: aiosqlite.Connection) -> Optional[aiosqlite.Row]:
    cursor = await db.execute("SELECT * FROM servers WHERE server_id = ?", (server_id,))
    return await cursor.fetchone()

async def verify_agent_api_key(request: Request, x_api_key: str = Header(...)):
    server_id = request.path_params.get("server_id")
    if not server_id: raise HTTPException(status_code=400, detail="Server ID missing")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        agent_record = await get_agent_from_db(server_id, db)
    if not agent_record or not pwd_context.verify(x_api_key, agent_record["api_key_hash"]):
        raise HTTPException(status_code=401, detail="Invalid Agent API Key")
    if server_id in server_live_status:
        server_live_status[server_id].api_key = x_api_key

# --- Main Application ---
app = FastAPI(title=settings.APP_NAME, version="6.2.0-STABLE")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory="templates")
server_live_status: Dict[str, 'ServerRecord'] = {}

@app.on_event("startup")
async def startup_event():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hashed_password TEXT NOT NULL)")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                server_id TEXT PRIMARY KEY, hostname TEXT, ip_address TEXT, port INTEGER, 
                os_info TEXT, server_group TEXT, api_key_hash TEXT, last_seen TIMESTAMP
            )""")
        admin_user = await get_user(db, settings.FIRST_ADMIN_USER)
        if not admin_user:
            hashed_password = get_password_hash(settings.FIRST_ADMIN_PASSWORD)
            await db.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (settings.FIRST_ADMIN_USER, hashed_password))
            logger.info(f"Created default admin user '{settings.FIRST_ADMIN_USER}'")
        await db.commit()
    logger.info("Database initialized. Fleet Command is ready.")
    await load_servers_from_db()

async def load_servers_from_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        records = await db.execute_fetchall("SELECT * FROM servers")
        for rec in records:
            server_id = rec["server_id"]
            if server_id not in server_live_status:
                 server_live_status[server_id] = ServerRecord(
                    server_id=server_id, hostname=rec["hostname"], ip_address=rec["ip_address"],
                    port=rec["port"], os_info=rec["os_info"], group=rec["server_group"],
                    last_seen=rec["last_seen"], api_key=None,
                    status=ServerStatusUpdate(cpu_usage=0, memory_usage=0, disk_usage=0, uptime="N/A")
                )

async def send_request_to_agent(server: ServerRecord, endpoint: str, payload: Optional[dict] = None) -> dict:
    if not server.api_key:
        raise HTTPException(status_code=424, detail="Agent key not available in cache. The agent must send a heartbeat to enable remote commands.")
    agent_url = f"http://{server.ip_address}:{server.port}/{endpoint}"
    headers = {"X-API-Key": server.api_key}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(agent_url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as e:
        return {"error": f"Agent unreachable: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}

# --- Auth Endpoints ---
@app.get("/login", response_class=HTMLResponse, tags=["Auth"])
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/token", tags=["Auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        user = await get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

# --- UI & API Endpoints (Secured) ---
@app.get("/", response_class=HTMLResponse, tags=["UI"], dependencies=[Depends(get_current_active_user)])
async def get_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/servers/status", response_model=List[ServerRecord], tags=["API"], dependencies=[Depends(get_current_active_user)])
async def get_all_servers_status_api():
    return list(server_live_status.values())

# --- Agent Endpoints ---
@app.post("/agent/register", response_model=AgentRegistrationResponse, tags=["Agent"])
async def register_agent(agent_info: ServerAgentInfo, dependencies=[Depends(verify_master_key)]):
    server_id, now = agent_info.hostname, datetime.datetime.utcnow()
    new_api_key = generate_api_key()
    hashed_api_key = get_password_hash(new_api_key)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("DELETE FROM servers WHERE server_id = ?", (server_id,))
        await db.execute("INSERT INTO servers (server_id, hostname, ip_address, port, os_info, server_group, api_key_hash, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (server_id, agent_info.hostname, agent_info.ip_address, agent_info.port, agent_info.os_info, agent_info.group, hashed_api_key, now))
        await db.commit()
    server_live_status[server_id] = ServerRecord(server_id=server_id, status=ServerStatusUpdate(cpu_usage=0, memory_usage=0, disk_usage=0, uptime="N/A"), last_seen=now, api_key=new_api_key, **agent_info.dict())
    return AgentRegistrationResponse(server_id=server_id, api_key=new_api_key, message="Registration successful. Store this API key securely.")

@app.post("/agent/heartbeat/{server_id}", tags=["Agent"], dependencies=[Depends(verify_agent_api_key)])
async def agent_heartbeat(server_id: str, status: ServerStatusUpdate):
    if server_id not in server_live_status:
        await load_servers_from_db()
        if server_id not in server_live_status: raise HTTPException(404, "Server not found.")
    now = datetime.datetime.utcnow()
    server_live_status[server_id].status = status
    server_live_status[server_id].last_seen = now
    return {"status": "ok"}

# --- Admin Actions (Secured) ---
@app.post("/api/servers/{server_id}/execute-command", response_model=CommandResponse, tags=["Admin Actions"])
async def execute_command(server_id: str, request: CommandRequest, current_user: User = Depends(get_current_active_user)):
    if server_id not in server_live_status:
        raise HTTPException(status_code=404, detail="Server not found.")
    logger.info(f"User '{current_user.username}' executing command on '{server_id}'")
    server = server_live_status[server_id]
    result = await send_request_to_agent(server, "execute-command", payload={"command": request.command})
    return CommandResponse(server_id=server_id, command=request.command, **result)

# ==============================================================================
# File: agent.py
# Version: 2.1 (Stable)
# ==============================================================================
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Header
import platform
import psutil
import subprocess
import time
import threading
import httpx
import logging
import datetime
import os
from pathlib import Path

# --- Agent Configuration (Loaded from Environment Variables) ---
class AgentSettings:
    def __init__(self):
        self.HOSTNAME = os.getenv("AGENT_HOSTNAME", platform.node())
        self.IP_ADDRESS = os.getenv("AGENT_IP_ADDRESS", "127.0.0.1")
        self.PORT = int(os.getenv("AGENT_PORT", 8001))
        self.GROUP = os.getenv("AGENT_GROUP", "default")
        self.MAIN_SERVER_URL = os.getenv("MAIN_SERVER_URL", "http://127.0.0.1:8000")
        self.MASTER_REGISTRATION_KEY = os.getenv("MASTER_REGISTRATION_KEY", "NOT_SET")
        self.HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", 30))
        self.KEY_STORAGE_FILE = Path("./.agent_key")
        self.AGENT_API_KEY = self.load_api_key()

    def load_api_key(self) -> str | None:
        return self.KEY_STORAGE_FILE.read_text().strip() if self.KEY_STORAGE_FILE.exists() else None

    def save_api_key(self, api_key: str):
        self.KEY_STORAGE_FILE.write_text(api_key)
        self.AGENT_API_KEY = api_key

settings_agent = AgentSettings()
agent_app = FastAPI()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - AGENT - %(levelname)s - %(message)s')
logger_agent = logging.getLogger(__name__)

# --- Agent Core Functions ---
def get_system_metrics():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime_seconds = (datetime.datetime.now() - boot_time).total_seconds()
    uptime_str = str(datetime.timedelta(seconds=int(uptime_seconds)))
    return {"cpu_usage": psutil.cpu_percent(interval=1), "memory_usage": mem.percent, "disk_usage": disk.percent, "uptime": uptime_str}

def run_command(command: str):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, check=False)
        return {"stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except Exception as e:
        return {"error": f"Command execution failed: {e}"}

# --- Agent Endpoints ---
async def verify_api_key_agent(x_api_key: str = Header(...)):
    if not settings_agent.AGENT_API_KEY or x_api_key != settings_agent.AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid Agent API Key")

@agent_app.post("/execute-command", dependencies=[Depends(verify_api_key_agent)])
async def execute_command_endpoint(request: Request):
    data = await request.json()
    command = data.get("command")
    logger_agent.info(f"Executing command: {command}")
    return run_command(command)

# --- Heartbeat & Registration Logic ---
def heartbeat_and_registration_thread():
    if not settings_agent.AGENT_API_KEY:
        logger_agent.info("No API key found. Attempting to register with the main server...")
        register_payload = {
            "hostname": settings_agent.HOSTNAME, "ip_address": settings_agent.IP_ADDRESS,
            "port": settings_agent.PORT, "os_info": f"{platform.system()} {platform.release()}", "group": settings_agent.GROUP
        }
        headers = {"X-Master-Key": settings_agent.MASTER_REGISTRATION_KEY}
        try:
            with httpx.Client() as client:
                response = client.post(f"{settings_agent.MAIN_SERVER_URL}/agent/register", json=register_payload, headers=headers, timeout=20)
                response.raise_for_status()
                data = response.json()
                settings_agent.save_api_key(data["api_key"])
                logger_agent.info("Registration successful. New API key has been saved locally.")
        except Exception as e:
            logger_agent.critical(f"CRITICAL: Agent registration failed: {e}. The agent cannot start.")
            return

    logger_agent.info("Starting heartbeat loop...")
    while True:
        try:
            metrics = get_system_metrics()
            headers = {"X-API-Key": settings_agent.AGENT_API_KEY}
            with httpx.Client() as client:
                response = client.post(f"{settings_agent.MAIN_SERVER_URL}/agent/heartbeat/{settings_agent.HOSTNAME}", json=metrics, headers=headers, timeout=10)
                if response.status_code != 200:
                    logger_agent.warning(f"Heartbeat failed. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logger_agent.error(f"Error in heartbeat loop: {e}")
        time.sleep(settings_agent.HEARTBEAT_INTERVAL)

if __name__ == "__main__":
    if __package__ is None: # Standalone execution
        hb_thread = threading.Thread(target=heartbeat_and_registration_thread, daemon=True)
        hb_thread.start()
        uvicorn.run(agent_app, host="0.0.0.0", port=settings_agent.PORT)
