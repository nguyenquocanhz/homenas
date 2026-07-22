# -*- coding: utf-8 -*-
# HomeNAS FastAPI Backend (app.py) với TOTP 2FA, Resend, Multipart Upload, SSD Cache (50GB) & Multi-Drive (SSD/HDD)

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
import mimetypes
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request, Response, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

try:
    from pyresend import Resend, templates as email_templates
except ImportError:
    Resend = None
    email_templates = None

# Thư mục lưu trữ 2 phân vùng SSD và HDD
STORAGE_SSD_DIR = os.getenv("STORAGE_DIR", "./storage")
STORAGE_HDD_DIR = os.getenv("STORAGE_HDD_DIR", "./storage-hdd")
SSD_CACHE_DIR = os.getenv("SSD_CACHE_DIR", "")
MAX_CACHE_SIZE_GB = int(os.getenv("MAX_CACHE_SIZE_GB", "50")) # 50GB SSD Cache

TMP_CHUNKS_DIR = os.path.join(SSD_CACHE_DIR if SSD_CACHE_DIR else STORAGE_SSD_DIR, ".tmp_chunks")

os.makedirs(STORAGE_SSD_DIR, exist_ok=True)
os.makedirs(STORAGE_HDD_DIR, exist_ok=True)
os.makedirs(TMP_CHUNKS_DIR, exist_ok=True)
if SSD_CACHE_DIR:
    os.makedirs(SSD_CACHE_DIR, exist_ok=True)

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "naspassword123")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")

ACTIVE_SESSIONS = set()
RESEND_CONFIG_FILE = "resend_config.json"

app = FastAPI(title="HomeNAS Server", version="1.8.0")
templates = Jinja2Templates(directory="templates")

# --- SSD Cache Cleanup & Sync Helpers ---

def clean_old_ssd_cache():
    if not SSD_CACHE_DIR or not os.path.exists(SSD_CACHE_DIR):
        return
    try:
        total_size = sum(os.path.getsize(os.path.join(SSD_CACHE_DIR, f)) for f in os.listdir(SSD_CACHE_DIR) if os.path.isfile(os.path.join(SSD_CACHE_DIR, f)))
        max_bytes = MAX_CACHE_SIZE_GB * 1024 * 1024 * 1024

        if total_size > max_bytes:
            files = [os.path.join(SSD_CACHE_DIR, f) for f in os.listdir(SSD_CACHE_DIR) if os.path.isfile(os.path.join(SSD_CACHE_DIR, f))]
            files.sort(key=os.path.getmtime)
            for f in files:
                try:
                    os.remove(f)
                    total_size -= os.path.getsize(f)
                    if total_size <= max_bytes * 0.8:
                        break
                except Exception:
                    continue
    except Exception as e:
        print(f"Lỗi dọn dẹp SSD Cache: {e}")

def sync_ssd_cache_to_storage(cache_file_path: str, target_file_path: str):
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
    """Đảm bảo đường dẫn nằm trong STORAGE_SSD_DIR hoặc STORAGE_HDD_DIR"""
    rel_path = rel_path.replace("\\", "/").strip("/")
    if rel_path.startswith("ssd"):
        base = Path(STORAGE_SSD_DIR).resolve()
        sub = rel_path[3:].lstrip("/")
        target = (base / sub).resolve()
        if not str(target).startswith(str(base)):
            raise HTTPException(status_code=403, detail="Access Denied: Path traversal detected")
        return target
    elif rel_path.startswith("hdd"):
        base = Path(STORAGE_HDD_DIR).resolve()
        sub = rel_path[3:].lstrip("/")
        target = (base / sub).resolve()
        if not str(target).startswith(str(base)):
            raise HTTPException(status_code=403, detail="Access Denied: Path traversal detected")
        return target
    else:
        raise HTTPException(status_code=400, detail="Không thể tạo file/thư mục ở thư mục gốc! Vui lòng truy cập SSD Storage hoặc HDD Storage.")

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

# --- Video Streaming Engine (HTTP 206) ---

@app.get("/api/stream")
async def stream_video(request: Request, path: str = Query(...)):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    target = get_safe_path(path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Video file not found")

    file_size = target.stat().st_size
    mime_type, _ = mimetypes.guess_type(target)
    if not mime_type:
        ext = target.suffix.lower()
        if ext == ".mkv": mime_type = "video/x-matroska"
        elif ext == ".mp4": mime_type = "video/mp4"
        elif ext == ".webm": mime_type = "video/webm"
        elif ext == ".mov": mime_type = "video/quicktime"
        elif ext == ".avi": mime_type = "video/x-msvideo"
        else: mime_type = "video/mp4"

    range_header = request.headers.get("range")
    
    if range_header:
        bytes_type, bytes_range = range_header.split("=")
        if bytes_type.strip() != "bytes":
            raise HTTPException(status_code=416, detail="Requested Range Not Satisfiable")

        start_str, end_str = bytes_range.split("-")
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else file_size - 1

        if start >= file_size or end >= file_size:
            raise HTTPException(status_code=416, detail="Requested Range Not Satisfiable")

        chunk_size = (end - start) + 1

        def stream_generator():
            with open(target, "rb") as f:
                f.seek(start)
                bytes_left = chunk_size
                while bytes_left > 0:
                    read_bytes = min(1024 * 1024, bytes_left)
                    data = f.read(read_bytes)
                    if not data:
                        break
                    bytes_left -= len(data)
                    yield data

        headers = {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(chunk_size),
            "Content-Type": mime_type
        }
        return StreamingResponse(stream_generator(), status_code=206, headers=headers)
    else:
        return FileResponse(target, media_type=mime_type)

# --- Multipart Chunked Upload Engine ---

@app.post("/api/upload/init")
async def init_multipart_upload(
    request: Request,
    filename: str = Form(...),
    total_size: int = Form(...),
    total_chunks: int = Form(...),
    path: str = Form("")
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    if not path.replace("\\", "/").strip("/"):
        raise HTTPException(status_code=400, detail="Không thể tải file lên thư mục gốc! Vui lòng chọn SSD Storage hoặc HDD Storage.")

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

    disk_ssd = psutil.disk_usage(STORAGE_SSD_DIR)
    disk_hdd = psutil.disk_usage(STORAGE_HDD_DIR)
    mem = psutil.virtual_memory()

    ssd_stats = None
    if SSD_CACHE_DIR and os.path.exists(SSD_CACHE_DIR):
        try:
            used_bytes = sum(
                os.path.getsize(os.path.join(SSD_CACHE_DIR, f))
                for f in os.listdir(SSD_CACHE_DIR)
                if os.path.isfile(os.path.join(SSD_CACHE_DIR, f))
            )
        except Exception:
            used_bytes = 0
        
        max_bytes = MAX_CACHE_SIZE_GB * 1024 * 1024 * 1024
        free_bytes = max(0, max_bytes - used_bytes)
        percent = round((used_bytes / max_bytes) * 100, 1) if max_bytes > 0 else 0.0

        ssd_stats = {
            "used": format_size(used_bytes),
            "free": format_size(free_bytes),
            "total": format_size(max_bytes),
            "percent": percent,
            "max_limit_gb": MAX_CACHE_SIZE_GB
        }

    # Trả về dung lượng gộp của cả 2 ổ làm dung lượng hệ thống chung
    return {
        "disk": {
            "total": format_size(disk_ssd.total + disk_hdd.total),
            "used": format_size(disk_ssd.used + disk_hdd.used),
            "free": format_size(disk_ssd.free + disk_hdd.free),
            "percent": round(((disk_ssd.used + disk_hdd.used) / (disk_ssd.total + disk_hdd.total)) * 100, 1)
        },
        "ssd_cache": ssd_stats,
        "memory": {"percent": mem.percent},
        "cpu": {"percent": psutil.cpu_percent(interval=0.1)}
    }

@app.get("/api/files")
async def list_files(request: Request, path: str = Query("")):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    path = path.replace("\\", "/").strip("/")

    if not path:
        # Danh mục ảo ở Thư mục gốc
        return {
            "current_path": "",
            "items": [
                {
                    "name": "SSD Storage (150GB)",
                    "path": "ssd",
                    "is_dir": True,
                    "size": "-",
                    "raw_size": 0,
                    "modified": "-",
                    "ext": "",
                    "icon": "folder"
                },
                {
                    "name": "HDD Storage (357GB)",
                    "path": "hdd",
                    "is_dir": True,
                    "size": "-",
                    "raw_size": 0,
                    "modified": "-",
                    "ext": "",
                    "icon": "folder"
                }
            ]
        }

    target = get_safe_path(path)
    if not target.exists() or not target.is_dir():
        raise HTTPException(status_code=404, detail="Directory not found")

    items = []
    base_dir = Path(STORAGE_SSD_DIR).resolve() if path.startswith("ssd") else Path(STORAGE_HDD_DIR).resolve()
    prefix = "ssd/" if path.startswith("ssd") else "hdd/"

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

            # Ghép relative path chuẩn với prefix ssd/ hoặc hdd/
            rel_item_path = prefix + str(p.relative_to(base_dir)).replace("\\", "/")

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

    if not path.replace("\\", "/").strip("/"):
        raise HTTPException(status_code=400, detail="Không thể tải file lên thư mục gốc! Vui lòng chọn SSD Storage hoặc HDD Storage.")

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

    if not path.replace("\\", "/").strip("/"):
        raise HTTPException(status_code=400, detail="Không thể tạo thư mục ở thư mục gốc! Vui lòng chọn SSD Storage hoặc HDD Storage.")

    target_dir = get_safe_path(path) / name
    if target_dir.exists():
        raise HTTPException(status_code=400, detail="Directory already exists")
    target_dir.mkdir(parents=True, exist_ok=True)
    return {"message": "Folder created successfully"}

@app.delete("/api/delete")
async def delete_item(request: Request, path: str = Query(...)):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthenticated")

    if not path.replace("\\", "/").strip("/"):
        raise HTTPException(status_code=400, detail="Không thể xóa ổ đĩa chính!")

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
    print(f"HomeNAS Server v1.8.0 (Multi-Drive & SSD Cache Buffer) running on port 8080.")
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)
