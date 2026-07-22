# HomeNAS Server 🏠💾

[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, self-hosted **Home NAS (Network Attached Storage)** system designed for Home Servers. Includes a modern Glassmorphism Web File Manager, Samba SMB Server for native Windows/Mac drive mapping, and Docker Compose for 1-click deployment.

---

## ✨ Features

- **🎨 Modern Dark Glassmorphism Web UI**: Responsive file browser with breadcrumbs, file type icons, and smooth transitions.
- **📊 Real-time Hardware Metrics**: Live monitoring for Disk Usage (Total, Used, Free), CPU %, and RAM %.
- **📂 Full File Management**: Browse directories, upload files via drag & drop, download files, create folders, and delete items.
- **💻 Native Network Drive Mapping (Samba SMB)**: Map your Home Server storage directly in **Windows File Explorer** (`\\server-ip\HomeNAS-Storage`) and **Mac Finder** (`smb://server-ip/HomeNAS-Storage`).
- **🐳 Docker 1-Click Deployment**: Containerized setup with `docker-compose`.

---

## 🚀 Quick Start (Docker Compose)

### 1. Clone the repository
```bash
git clone https://github.com/nguyenquocanhz/homenas.git
cd homenas
```

### 2. Start services
```bash
docker-compose up -d
```

### 3. Access your NAS
- **Web UI**: Open `http://<your-server-ip>:8080` in your browser.
- **Windows Explorer Mapping**: Press `Win + E`, right-click **This PC** -> **Map network drive**, type `\\<your-server-ip>\HomeNAS-Storage` (User: `admin`, Password: `naspassword123`).
- **Mac Finder**: In Finder, press `Cmd + K`, type `smb://<your-server-ip>/HomeNAS-Storage`.

---

## 🐍 Standalone Python Run

```bash
pip install -r requirements.txt
python app.py
```
Open `http://localhost:8080` in your browser.

---

## 📄 License

Distributed under the MIT License.
