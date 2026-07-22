# -*- coding: utf-8 -*-
# HomeNAS FastAPI Backend (app.py) với Bảo mật TOTP 2FA

import os
import time
import hmac
import struct
import base64
import hashlib
import shutil
import secrets
import psutil
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

STORAGE_DIR = os.getenv("STORAGE_DIR", "./storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

# Thông tin tài khoản đăng nhập (mặc định)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "naspassword123")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP") # Base32 TOTP secret

# Lưu danh sách session token hợp lệ
ACTIVE_SESSIONS = set()

app = FastAPI(title="HomeNAS Server", version="1.2.0")
templates = Jinja2Templates(directory="templates")

# --- Helper TOTP 2FA (RFC 6238 Standard - Google Authenticator / Authy) ---

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Xác thực mã TOTP 6 chữ số theo chuẩn RFC 6238 (Google Authenticator)"""
    if not code or len(code) != 6 or not code.isdigit():
        return False
    try:
        secret_clean = secret.upper().replace(' ', '').replace('-', '')
        padding = len(secret_clean) % 8
        if padding != 0:
            secret_clean += '=' * (8 - padding)
        key = base64.b32decode(secret_clean, casefold=True)
    except Exception:
        return False

    current_time = int(time.time()) // 30
    for i in range(-window, window + 1):
        t = current_time + i
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        truncated_hash = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
        totp = truncated_hash % 1000000
        if f"{totp:06d}" == code:
            return True
    return False

def is_authenticated(request: Request) -> bool:
    """Kiểm tra session cookie"""
    session_token = request.cookies.get("session_token")
    return session_token in ACTIVE_SESSIONS if session_token else False

def get_safe_path(rel_path: str) -> Path:
    """Đảm bảo đường dẫn nằm trong STORAGE_DIR (Bảo mật path traversal)"""
    base = Path(STORAGE_DIR).resolve()
    target = (base / rel_path.lstrip("/\\")).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(status_code=403, detail="Access Denied: Path traversal detected")
    return target

def format_size(bytes_size: int) -> str:
    """Format dung lượng dạng KB, MB, GB"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"

# --- Authentication Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/")
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/api/login")
async def api_login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(...)
):
    if username != ADMIN_USER or password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác!")

    if not verify_totp(TOTP_SECRET, totp_code):
        raise HTTPException(status_code=401, detail="Mã TOTP 2FA (Google Authenticator) không đúng!")

    token = secrets.token_hex(32)
    ACTIVE_SESSIONS.add(token)

    response = JSONResponse({"success": True, "message": "Đăng nhập thành công!"})
    response.set_cookie(key="session_token", value=token, httponly=True, max_age=86400*7) # 7 ngày
    return response

@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(token)
    res = JSONResponse({"success": True})
    res.delete_cookie("session_token")
    return res

@app.get("/api/totp-setup")
async def get_totp_setup():
    """Trả về Secret Key cho Google Authenticator / Authy"""
    return {
        "secret": TOTP_SECRET,
        "otpauth_url": f"otpauth://totp/HomeNAS:{ADMIN_USER}?secret={TOTP_SECRET}&issuer=HomeNAS"
    }

# --- Protected App Routes ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/system")
async def get_system_stats(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    disk = psutil.disk_usage(STORAGE_DIR)
    mem = psutil.virtual_memory()
    return {
        "disk": {
            "total": format_size(disk.total),
            "used": format_size(disk.used),
            "free": format_size(disk.free),
            "percent": disk.percent
        },
        "memory": {"percent": mem.percent},
        "cpu": {"percent": psutil.cpu_percent(interval=0.1)}
    }

@app.get("/api/files")
async def list_files(request: Request, path: str = Query("")):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target = get_safe_path(path)
    if not target.exists() or not target.is_dir():
        raise HTTPException(status_code=404, detail="Directory not found")

    items = []
    for p in target.iterdir():
        try:
            stat = p.stat()
            is_dir = p.is_dir()
            ext = p.suffix.lower().replace(".", "") if not is_dir else ""
            
            icon_type = "folder" if is_dir else "file"
            if ext in ["jpg", "jpeg", "png", "gif", "webp", "svg"]: icon_type = "image"
            elif ext in ["mp4", "mkv", "avi", "mov", "webm"]: icon_type = "video"
            elif ext in ["mp3", "flac", "wav", "ogg", "m4a"]: icon_type = "audio"
            elif ext in ["zip", "rar", "tar", "gz", "7z"]: icon_type = "archive"
            elif ext in ["pdf", "doc", "docx", "txt", "md"]: icon_type = "document"

            rel_item_path = str(p.relative_to(Path(STORAGE_DIR).resolve())).replace("\\", "/")

            items.append({
                "name": p.name,
                "path": rel_item_path,
                "is_dir": is_dir,
                "size": format_size(stat.st_size) if not is_dir else "-",
                "raw_size": stat.st_size if not is_dir else 0,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "ext": ext,
                "icon": icon_type
            })
        except Exception:
            continue

    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return {"current_path": path, "items": items}

@app.post("/api/upload")
async def upload_file(request: Request, file: UploadFile = File(...), path: str = Form("")):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target_dir = get_safe_path(path)
    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(status_code=400, detail="Invalid directory")

    dest_path = target_dir / file.filename
    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"message": "Upload successful", "filename": file.filename}

@app.get("/api/download")
async def download_file(request: Request, path: str = Query(...)):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target = get_safe_path(path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(target, filename=target.name)

@app.post("/api/mkdir")
async def create_directory(request: Request, name: str = Form(...), path: str = Form("")):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target_dir = get_safe_path(path) / name
    if target_dir.exists():
        raise HTTPException(status_code=400, detail="Directory already exists")
    target_dir.mkdir(parents=True, exist_ok=True)
    return {"message": "Folder created successfully"}

@app.delete("/api/delete")
async def delete_item(request: Request, path: str = Query(...)):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target = get_safe_path(path)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Item not found")

    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()

    return {"message": "Deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    print(f"HomeNAS Server with TOTP 2FA running on port 8080. Storage: {os.path.abspath(STORAGE_DIR)}")
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)
