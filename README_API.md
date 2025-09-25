# 华为验证服务器 API 文档

## 概述
本服务器提供华为账号验证相关的API接口，支持两种主要的验证方式：
1. 直接使用idToken验证OpenID和UnionID的有效性
2. 使用serverAuthCode换取idToken后再验证OpenID和UnionID的有效性

## API 接口

### 1. 直接验证idToken
**接口地址：** `POST /verify_id_token`

**请求参数：**
```json
{
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "idToken验证成功并提取用户信息",
    "data": {
        "user_info": {
            "openId": "user_open_id",
            "unionId": "user_union_id",
            "email": "user@example.com",
            "name": "用户名",
            "picture": "头像URL",
            "aud": "应用ID",
            "iss": "发行者",
            "exp": 1234567890,
            "iat": 1234567890
        },
        "token_valid": true,
        "decoded_token": {...}
    }
}
```

### 2. 使用serverAuthCode验证
**接口地址：** `POST /verify_server_auth_code`

**请求参数：**
```json
{
    "server_auth_code": "CF_xxxxxxxxxxxxxxxxx"
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "使用serverAuthCode验证成功",
    "data": {
        "token_info": {
            "access_token": "CF_xxxxxxxxxxxxxxxxx",
            "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "CF_xxxxxxxxxxxxxxxxx",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "openid profile"
        },
        "user_info": {
            "openId": "user_open_id",
            "unionId": "user_union_id",
            "email": "user@example.com",
            "name": "用户名"
        },
        "token_valid": true,
        "verification_method": "server_auth_code"
    }
}
```

### 3. 使用access_token获取用户信息
**接口地址：** `POST /get_user_info_by_access_token`

**请求参数：**
```json
{
    "access_token": "CF_xxxxxxxxxxxxxxxxx"
}
```

**响应示例：**
```json
{
    "success": true,
    "message": "成功获取用户信息",
    "data": {
        "user_info": {
            "openId": "user_open_id",
            "unionId": "user_union_id",
            "displayName": "用户显示名",
            "email": "user@example.com",
            "headPictureURL": "头像URL",
            "gender": 1,
            "countryCode": "CN"
        },
        "raw_response": {...}
    }
}
```

### 4. 健康检查
**接口地址：** `GET /health`

**响应示例：**
```json
{
    "status": "healthy",
    "timestamp": "2024-01-01T00:00:00Z"
}
```

## 错误响应格式
所有接口在出错时都会返回统一的错误格式：

```json
{
    "success": false,
    "error": "错误描述",
    "error_code": "错误代码",
    "status_code": 400
}
```

## 常见错误码
- `missing_parameter`: 缺少必需参数
- `invalid_id_token`: idToken无效
- `no_id_token`: 未获取到id_token
- `network_error`: 网络请求异常
- `internal_error`: 服务器内部错误

## 使用示例

### Python 示例
```python
import requests

# 验证idToken
response = requests.post('http://localhost:5000/verify_id_token', json={
    'id_token': 'your_id_token_here'
})
result = response.json()

# 使用serverAuthCode验证
response = requests.post('http://localhost:5000/verify_server_auth_code', json={
    'server_auth_code': 'your_server_auth_code_here'
})
result = response.json()
```

### JavaScript 示例
```javascript
// 验证idToken
fetch('/verify_id_token', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        id_token: 'your_id_token_here'
    })
})
.then(response => response.json())
.then(data => console.log(data));

// 使用serverAuthCode验证
fetch('/verify_server_auth_code', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        server_auth_code: 'your_server_auth_code_here'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

## 部署说明
1. 确保已安装所有依赖：`pip install -r requirements.txt`
2. 配置config.py中的华为应用信息
3. 启动服务：`python app.py` 或 `uvicorn app:app --host 0.0.0.0 --port 5000 --workers 4`
4. 访问API文档：`http://localhost:5000/docs` (FastAPI自动生成)