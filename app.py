# -*- coding: utf-8 -*-
# HomeNAS FastAPI Backend (app.py) với Bảo mật TOTP 2FA, Resend Email Alert, Multipart Upload & SSD Cache Engine (Giới hạn 32GB)

import os
import json
import time
import hmac
import struct
import base64
import hashlib
import shutil
import secrets
import random
import asyncio
import psutil
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request, Response, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

try:
    from pyresend import Resend, templates as email_templates
except ImportError:
    Resend = None
    email_templates = None

STORAGE_DIR = os.getenv("STORAGE_DIR", "./storage")
SSD_CACHE_DIR = os.getenv("SSD_CACHE_DIR", "")  # Đường dẫn đệm SSD Cache
MAX_CACHE_SIZE_GB = int(os.getenv("MAX_CACHE_SIZE_GB", "32")) # Giới hạn 32GB

TMP_CHUNKS_DIR = os.path.join(SSD_CACHE_DIR if SSD_CACHE_DIR else STORAGE_DIR, ".tmp_chunks")

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(TMP_CHUNKS_DIR, exist_ok=True)
if SSD_CACHE_DIR:
    os.makedirs(SSD_CACHE_DIR, exist_ok=True)

# Thông tin tài khoản đăng nhập (mặc định)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "naspassword123")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")

ACTIVE_SESSIONS = set()
RESEND_CONFIG_FILE = "resend_config.json"

app = FastAPI(title="HomeNAS Server", version="1.6.0")
templates = Jinja2Templates(directory="templates")

# --- SSD Cache Cleanup & Sync Helpers ---

def clean_old_ssd_cache():
    """Tự động kiểm tra và dọn dẹp SSD Cache nếu vượt quá giới hạn 32GB"""
    if not SSD_CACHE_DIR or not os.path.exists(SSD_CACHE_DIR):
        return
    try:
        total_size = sum(os.path.getsize(os.path.join(SSD_CACHE_DIR, f)) for f in os.listdir(SSD_CACHE_DIR) if os.path.isfile(os.path.join(SSD_CACHE_DIR, f)))
        max_bytes = MAX_CACHE_SIZE_GB * 1024 * 1024 * 1024

        if total_size > max_bytes:
            # Xóa các file đệm cũ nhất đến khi dưới mức giới hạn
            files = [os.path.join(SSD_CACHE_DIR, f) for f in os.listdir(SSD_CACHE_DIR) if os.path.isfile(os.path.join(SSD_CACHE_DIR, f))]
            files.sort(key=os.path.getmtime)
            for f in files:
                try:
                    os.remove(f)
                    total_size -= os.path.getsize(f)
                    if total_size <= max_bytes * 0.8: # Dọn về mức 80% dung lượng tối đa
                        break
                except Exception:
                    continue
    except Exception as e:
        print(f"Lỗi dọn dẹp SSD Cache: {e}")

def sync_ssd_cache_to_storage(cache_file_path: str, target_file_path: str):
    """Chuyển file từ SSD Cache sang ổ đĩa HDD chính chạy ngầm và dọn dẹp đệm"""
    try:
        shutil.move(cache_file_path, target_file_path)
    except Exception as e:
        print(f"Error syncing SSD cache: {e}")
    finally:
        clean_old_ssd_cache()

# --- Resend Config Helpers ---

def load_resend_config() -> dict:
    if os.path.exists(RESEND_CONFIG_FILE):
        try:
            with open(RESEND_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "api_key": os.getenv("RESEND_API_KEY", "re_JQ6uJLyg_5oUMtDYUn31v7sTPU2gHSNxi"),
        "from_email": os.getenv("RESEND_FROM_EMAIL", "Acme <onboarding@resend.dev>"),
        "notify_email": os.getenv("NOTIFY_EMAIL", "delivered@resend.dev")
    }

def save_resend_config_data(api_key: str, from_email: str, notify_email: str):
    data = {
        "api_key": api_key.strip(),
        "from_email": from_email.strip(),
        "notify_email": notify_email.strip()
    }
    with open(RESEND_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data

# --- Helper TOTP 2FA ---

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
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
    session_token = request.cookies.get("session_token")
    return session_token in ACTIVE_SESSIONS if session_token else False

def get_safe_path(rel_path: str) -> Path:
    base = Path(STORAGE_DIR).resolve()
    target = (base / rel_path.lstrip("/\\")).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(status_code=403, detail="Access Denied")
    return target

def format_size(bytes_size: int) -> str:
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

    res = JSONResponse({"success": True, "message": "Đăng nhập thành công!"})
    res.set_cookie(key="session_token", value=token, httponly=True, max_age=86400*7)
    return res

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
    return {
        "secret": TOTP_SECRET,
        "otpauth_url": f"otpauth://totp/HomeNAS:{ADMIN_USER}?secret={TOTP_SECRET}&issuer=HomeNAS"
    }

# --- Resend Email Routes ---

@app.get("/api/resend-config")
async def get_resend_config(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")
    cfg = load_resend_config()
    masked_key = cfg["api_key"][:6] + "..." + cfg["api_key"][-4:] if len(cfg["api_key"]) > 10 else cfg["api_key"]
    return {
        "api_key": cfg["api_key"],
        "masked_api_key": masked_key,
        "from_email": cfg["from_email"],
        "notify_email": cfg["notify_email"]
    }

@app.post("/api/save-resend-config")
async def save_resend_config(
    request: Request,
    api_key: str = Form(...),
    from_email: str = Form(...),
    notify_email: str = Form(...)
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    if not api_key.startswith("re_"):
        raise HTTPException(status_code=400, detail="Resend API Key phải bắt đầu bằng 're_'!")

    save_resend_config_data(api_key, from_email, notify_email)
    return {"message": "Đã lưu cấu hình Resend API thành công!"}

@app.post("/api/send-verification-email")
async def send_verification_email(request: Request, target_email: Optional[str] = Form(None)):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    if Resend is None:
        raise HTTPException(status_code=500, detail="Thư viện pyresend chưa được cài đặt!")

    cfg = load_resend_config()
    to_email = target_email.strip() if target_email else cfg["notify_email"]
    if not to_email:
        raise HTTPException(status_code=400, detail="Vui lòng cung cấp Email người nhận!")

    code = f"{random.randint(100000, 999999)}"

    if email_templates:
        html_content = email_templates.promotional(
            title="Mã Xác Thực Bảo Mật HomeNAS",
            discount_code=code,
            discount_text="Mã xác thực 6 chữ số có hiệu lực trong 5 phút",
            description="Bạn vừa yêu cầu mã xác thực email hoặc cảnh báo bảo mật từ hệ thống HomeNAS Server.",
            button_text="Truy cập HomeNAS Server",
            button_url="http://localhost:8080",
            brand_name="HomeNAS Security"
        )
    else:
        html_content = f"<h2>Mã xác thực HomeNAS: {code}</h2>"

    try:
        client = Resend(api_key=cfg["api_key"])
        res = client.send_email(
            from_email=cfg["from_email"],
            to=to_email,
            subject=f"🔐 Mã Xác Thực HomeNAS: [{code}]",
            html=html_content
        )
        return {
            "success": True,
            "message": f"Đã gửi email xác thực tới {to_email} thành công!",
            "email_id": res.get("id"),
            "code": code
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Gửi mail qua Resend thất bại: {str(ex)}")

# --- Multipart Chunked Upload Engine & SSD Write Cache (Max 32GB) ---

@app.post("/api/upload/init")
async def init_multipart_upload(
    request: Request,
    filename: str = Form(...),
    total_size: int = Form(...),
    total_chunks: int = Form(...)
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    clean_old_ssd_cache()

    upload_id = f"up_{secrets.token_hex(8)}"
    upload_dir = os.path.join(TMP_CHUNKS_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)

    info = {
        "upload_id": upload_id,
        "filename": filename,
        "total_size": total_size,
        "total_chunks": total_chunks,
        "created_at": time.time()
    }
    with open(os.path.join(upload_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(info, f)

    return {"upload_id": upload_id, "total_chunks": total_chunks}

@app.post("/api/upload/chunk")
async def upload_chunk(
    request: Request,
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    chunk_file: UploadFile = File(...)
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    upload_dir = os.path.join(TMP_CHUNKS_DIR, upload_id)
    if not os.path.exists(upload_dir):
        raise HTTPException(status_code=404, detail="Upload session not found")

    chunk_path = os.path.join(upload_dir, f"chunk_{chunk_index:05d}.part")
    with open(chunk_path, "wb") as buffer:
        shutil.copyfileobj(chunk_file.file, buffer)

    return {"status": "ok", "chunk_index": chunk_index}

@app.post("/api/upload/complete")
async def complete_multipart_upload(
    request: Request,
    background_tasks: BackgroundTasks,
    upload_id: str = Form(...),
    path: str = Form("")
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    upload_dir = os.path.join(TMP_CHUNKS_DIR, upload_id)
    meta_path = os.path.join(upload_dir, "meta.json")

    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="Upload session not found")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    target_dir = get_safe_path(path)
    final_file_path = target_dir / meta["filename"]

    total_chunks = meta["total_chunks"]

    if SSD_CACHE_DIR and os.path.exists(SSD_CACHE_DIR):
        cache_file_path = os.path.join(SSD_CACHE_DIR, f"{upload_id}_{meta['filename']}")
        with open(cache_file_path, "wb") as cache_file:
            for i in range(total_chunks):
                part_path = os.path.join(upload_dir, f"chunk_{i:05d}.part")
                with open(part_path, "rb") as part_file:
                    shutil.copyfileobj(part_file, cache_file)

        background_tasks.add_task(sync_ssd_cache_to_storage, cache_file_path, str(final_file_path))
    else:
        with open(final_file_path, "wb") as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(upload_dir, f"chunk_{i:05d}.part")
                with open(part_path, "rb") as part_file:
                    shutil.copyfileobj(part_file, final_file)

    shutil.rmtree(upload_dir, ignore_errors=True)

    return {
        "message": f"Multipart upload completed! Accelerated with SSD Cache (Max {MAX_CACHE_SIZE_GB}GB)",
        "filename": meta["filename"]
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

    ssd_stats = None
    if SSD_CACHE_DIR and os.path.exists(SSD_CACHE_DIR):
        s_disk = psutil.disk_usage(SSD_CACHE_DIR)
        ssd_stats = {
            "used": format_size(s_disk.used),
            "free": format_size(s_disk.free),
            "total": format_size(s_disk.total),
            "percent": s_disk.percent,
            "max_limit_gb": MAX_CACHE_SIZE_GB
        }

    return {
        "disk": {
            "total": format_size(disk.total),
            "used": format_size(disk.used),
            "free": format_size(disk.free),
            "percent": disk.percent
        },
        "ssd_cache": ssd_stats,
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
            if p.name.startswith("."):
                continue

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
    print(f"HomeNAS Server v1.6.0 (SSD Cache Max Limit: {MAX_CACHE_SIZE_GB}GB) running on port 8080. Storage: {os.path.abspath(STORAGE_DIR)}")
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)
