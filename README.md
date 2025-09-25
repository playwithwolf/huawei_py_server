# 华为认证服务器 (Python版本)

基于华为Account-Server-Java-Demo的Python实现，提供华为账号认证相关的API服务。

## 功能特性

- ✅ 通过授权码获取访问令牌 (对应Java Demo的TokenAPIDemo)
- ✅ 获取访问令牌信息 (对应Java Demo的GetTokenInfoAPIDemo)  
- ✅ 验证ID Token (对应Java Demo的IDTokenParser)
- ✅ 完整的错误处理和日志记录
- ✅ 配置管理和环境变量支持
- ✅ RESTful API设计

## 项目结构

```
huawei_py_server/
├── app.py              # Flask应用主文件
├── config.py           # 配置管理模块（包含华为参数）
├── huawei_auth.py      # 华为认证服务类
├── utils.py            # 工具模块(错误处理、日志记录)
├── requirements.txt    # Python依赖
├── test_server.py      # 测试脚本
└── README.md          # 项目文档
```

## 快速开始

### 1. 安装依赖

```bash
cd d:\uniapp\huawei_py_server
pip install -r requirements.txt
```

### 2. 配置说明

华为AGC配置已经直接写在 <mcfile name="config.py" path="d:\uniapp\huawei_py_server\config.py"></mcfile> 文件中：

```python
# 华为AGC配置 - 直接在代码中设置
HUAWEI_CLIENT_ID = '107917734'
HUAWEI_CLIENT_SECRET = 'f462eeae4f5642a0a91d6edc9b1d64c6'
HUAWEI_PROJECT_ID = '99536292104595456'
HUAWEI_DEVELOPER_ID = '1781922428767748032'
```

如需修改配置，请直接编辑 `config.py` 文件。

### 3. 启动服务器

```bash
cd d:\uniapp\huawei_py_server
python app.py
```

服务器将在 `http://localhost:5000` 启动。

## API接口

### 1. 健康检查

```http
GET /
```

**响应示例：**
```json
{
    "status": "ok",
    "message": "华为认证服务器运行正常",
    "version": "1.0.0"
}
```

### 2. 获取访问令牌

```http
POST /api/huawei/token
Content-Type: application/json

{
    "code": "授权码",
    "redirect_uri": "重定向URI",
    "grant_type": "authorization_code"
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "Token获取成功",
    "data": {
        "access_token": "访问令牌",
        "refresh_token": "刷新令牌",
        "expires_in": 3600,
        "token_type": "Bearer"
    },
    "timestamp": "2024-01-20T10:30:00"
}
```

### 3. 获取令牌信息

```http
POST /api/huawei/tokeninfo
Content-Type: application/json

{
    "access_token": "访问令牌"
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "Token信息获取成功",
    "data": {
        "client_id": "客户端ID",
        "user_id": "用户ID",
        "expires_in": 3600,
        "scope": "openid profile"
    },
    "timestamp": "2024-01-20T10:30:00"
}
```

### 4. 验证ID Token

```http
POST /api/huawei/verify-idtoken
Content-Type: application/json

{
    "id_token": "ID令牌"
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "ID Token验证成功",
    "data": {
        "sub": "用户ID",
        "aud": "客户端ID",
        "iss": "https://oauth-login.cloud.huawei.com",
        "exp": 1642680600,
        "iat": 1642677000
    },
    "timestamp": "2024-01-20T10:30:00"
}
```

### 5. 获取配置信息

```http
GET /api/huawei/config
```

**响应示例：**
```json
{
    "success": true,
    "data": {
        "client_id": "客户端ID",
        "project_id": "项目ID",
        "token_url": "https://oauth-login.cloud.huawei.com/oauth2/v3/token",
        "tokeninfo_url": "https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo",
        "certs_url": "https://oauth-login.cloud.huawei.com/oauth2/v3/certs",
        "issuer": "https://oauth-login.cloud.huawei.com"
    }
}
```

## 错误处理

所有API都遵循统一的错误响应格式：

```json
{
    "success": false,
    "error": "错误描述",
    "error_code": "错误代码",
    "status_code": 400,
    "timestamp": "2024-01-20T10:30:00"
}
```

### 常见错误代码

- `MISSING_REQUIRED_FIELDS`: 缺少必需参数
- `INVALID_REQUEST_DATA`: 请求数据无效
- `TOKEN_REQUEST_FAILED`: Token请求失败
- `REQUEST_TIMEOUT`: 请求超时
- `NETWORK_ERROR`: 网络错误
- `INTERNAL_ERROR`: 服务器内部错误

## 日志记录

服务器会自动记录详细的日志信息：

- 控制台输出：实时查看服务器状态
- 文件记录：`huawei_auth.log` 文件保存完整日志
- 日志级别：INFO（生产环境）/ DEBUG（开发环境）

## 配置说明

### 华为AGC参数

所有华为AGC配置都直接写在 `config.py` 文件中，无需额外配置：

- **CLIENT_ID**: 107917734
- **CLIENT_SECRET**: f462eeae4f5642a0a91d6edc9b1d64c6  
- **PROJECT_ID**: 99536292104595456
- **DEVELOPER_ID**: 1781922428767748032

### 服务器配置

- **HOST**: 0.0.0.0 (监听所有网络接口)
- **PORT**: 5000 (服务端口)
- **DEBUG**: True (开发模式)

## 开发说明

### 项目依赖

- **Flask**: Web框架
- **requests**: HTTP客户端
- **PyJWT**: JWT处理
- **cryptography**: 加密算法支持

### 代码结构

- `app.py`: Flask应用和API路由
- `config.py`: 配置管理和环境变量处理
- `huawei_auth.py`: 华为认证核心逻辑
- `utils.py`: 工具函数、错误处理、日志记录

### 扩展开发

要添加新的API端点：

1. 在 `huawei_auth.py` 中添加业务逻辑
2. 在 `app.py` 中添加路由处理
3. 使用 `@handle_exceptions` 装饰器处理异常
4. 使用 `ResponseFormatter` 格式化响应

## 部署说明

### 生产环境部署

使用Gunicorn部署：

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker部署

创建 `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## 许可证

本项目基于华为Account-Server-Java-Demo改写，遵循相应的开源许可证。

## 支持

如有问题，请检查：

1. 环境变量配置是否正确
2. 华为AGC控制台配置是否匹配
3. 网络连接是否正常
4. 查看日志文件获取详细错误信息