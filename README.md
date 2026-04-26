# Secure File Management System (FastAPI)

这是一个基于 FastAPI 开发的安全文件管理系统，旨在提供高性能的文件存储与分享服务，并集成了端到端加密机制。

## 🚀 项目亮点 (Key Features)

*   **高性能后端**: 基于 **FastAPI** (ASGI) 框架，利用 Python `async/await` 异步特性处理高并发文件 I/O。
*   **端到端加密**: 采用 **AES-256-CBC** 算法对所有上传文件进行加密存储。每个文件拥有独立的随机密钥和 IV (Initialization Vector)，确保数据隐私。
*   **安全身份认证**: 使用 **JWT (JSON Web Tokens)** 进行无状态身份认证，支持 HttpOnly Cookie 防止 XSS 攻击。
*   **公钥基础设施 (PKI)**: 集成 **Elliptic Curve (ECC)** 密钥对生成，为未来的安全文件分享（基于公钥加密）打下基础。
*   **工程化部署**: 提供 **Docker** 和 **Docker Compose** 配置文件，支持一键拉起应用与数据库。

## 🛠️ 技术栈 (Tech Stack)

*   **Framework**: FastAPI
*   **Database**: MySQL 5.7 / 8.0
*   **ORM**: SQLAlchemy
*   **Security**: Cryptography (AES, ECC), Passlib (Bcrypt), Python-Jose (JWT)
*   **Validation**: Pydantic
*   **Deployment**: Docker, Uvicorn

## 🏁 快速开始 (Quick Start)

### 方式一：使用 Docker (推荐)

确保本地已安装 Docker 和 Docker Compose。

```bash
docker-compose up -d --build
```

访问: `http://localhost:8000`

### 方式二：本地开发环境

1.  **创建虚拟环境**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/Mac
    venv\Scripts\activate     # Windows
    ```

2.  **安装依赖**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **配置数据库**:
    确保本地 MySQL 运行中，并创建一个名为 `fwyaee` 的数据库。
    修改环境变量或 `app/config.py` 中的数据库连接字符串。

4.  **运行**:
    ```bash
    uvicorn main:app --reload
    ```

## 📚 API 文档

启动服务后，访问 Swagger UI 查看完整的 API 文档：
*   **URL**: `http://localhost:8000/docs`

## 🔒 安全设计细节

### 文件加密流程
1.  用户上传文件。
2.  后端生成随机 32 字节 AES Key 和 16 字节 IV。
3.  使用 AES-CBC 模式对文件流进行加密（PKCS7 Padding）。
4.  密文保存到磁盘，Key 和 IV (部分) 保存到数据库。
    *   *注：生产环境中，Key 应使用 Master Key 或用户公钥进行再加密（Envelope Encryption）。*

### 权限控制
*   使用 FastAPI 的依赖注入 (`Depends`) 系统进行统一的权限校验。
*   `get_current_user` 依赖自动解析 Token 并注入当前用户对象。

---
*Created for Graduation Project & Interview Portfolio*
