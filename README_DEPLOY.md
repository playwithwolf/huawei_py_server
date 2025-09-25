# 华为验证服务器 - Render.com 部署指南

## 项目概述

这是一个基于 **FastAPI** 的华为AGC认证服务器，提供华为账号验证和用户信息获取功能。

## 部署方式

### 方式一：使用 Procfile（推荐）

1. 确保项目根目录包含 `Procfile` 文件：
```
web: uvicorn app:app --host 0.0.0.0 --port $PORT --workers 4
```

2. 在 Render.com 创建新的 Web Service
3. 连接你的 GitHub 仓库
4. 配置构建设置：
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: 留空（使用 Procfile）

### 方式二：使用 render.yaml

1. 确保项目根目录包含 `render.yaml` 文件
2. 在 Render.com 选择 "New" -> "Blueprint"
3. 连接包含 `render.yaml` 的仓库

## 环境变量配置

在 Render.com 的环境变量设置中添加以下变量：

```
FASTAPI_ENV=production
FASTAPI_DEBUG=False
HUAWEI_CLIENT_ID=107917734
HUAWEI_CLIENT_SECRET=f462eeae4f5642a0a91d6edc9b1d64c6
HUAWEI_PROJECT_ID=99536292104595456
HUAWEI_DEVELOPER_ID=1781922428767748032
```

## 构建和启动命令

- **构建命令**: `pip install -r requirements.txt`
- **启动命令**: `uvicorn app:app --host 0.0.0.0 --port $PORT --workers 4`

## 重要说明

### 1. 端口配置
- Render.com 会自动设置 `$PORT` 环境变量
- 应用会自动使用该端口，无需手动配置

### 2. 框架对比
- **FastAPI**: 使用 `uvicorn` 作为 ASGI 服务器
- **Flask**: 使用 `gunicorn` 作为 WSGI 服务器

### 3. 配置说明
- `FASTAPI_ENV`: 设置为 `production` 用于生产环境
- `FASTAPI_DEBUG`: 设置为 `False` 禁用调试模式
- 华为相关配置：根据你的华为开发者账号设置

## 验证部署

部署成功后，访问以下端点验证：

1. **健康检查**: `GET /`
2. **配置信息**: `GET /api/huawei/config`
3. **API文档**: `GET /docs` (FastAPI自动生成)

## 故障排除

1. **构建失败**: 检查 `requirements.txt` 中的依赖版本
2. **启动失败**: 确认使用 `uvicorn` 而不是 `gunicorn`
3. **环境变量**: 确保所有必需的环境变量都已设置
4. **端口问题**: 确保使用 `$PORT` 环境变量

## API 接口

详细的API接口文档请参考 `README_API.md` 文件。