from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import logging
import os
from config import Config
from huawei_auth import HuaweiAuthService
from utils import ResponseFormatter
import uvicorn

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建FastAPI应用
app = FastAPI(
    title="华为认证服务器",
    description="华为AGC认证服务API",
    version="1.0.0"
)

# 初始化华为认证服务
huawei_auth = HuaweiAuthService()

# Pydantic模型定义
class IdTokenRequest(BaseModel):
    id_token: str

class ServerAuthCodeRequest(BaseModel):
    server_auth_code: str

class AccessTokenRequest(BaseModel):
    access_token: str

class TokenRequest(BaseModel):
    code: str
    redirect_uri: str
    grant_type: str = "authorization_code"

class TokenInfoRequest(BaseModel):
    access_token: str

class AGCTokenRequest(BaseModel):
    access_token: str

@app.post("/verify_id_token")
async def verify_id_token(request: IdTokenRequest):
    """
    直接使用idToken验证OpenID和UnionID的有效性
    """
    try:
        # 验证idToken并提取用户信息
        result = huawei_auth.verify_id_token_and_get_user_info(request.id_token)
        
        return result
        
    except Exception as e:
        logger.error(f"验证idToken接口异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500)
        )

@app.post("/verify_server_auth_code")
async def verify_server_auth_code(request: ServerAuthCodeRequest):
    """
    使用serverAuthCode换取idToken后再验证OpenID和UnionID的有效性
    """
    try:
        # 第一步：使用serverAuthCode换取access_token和id_token
        token_result = huawei_auth.exchange_id_token_by_server_auth_code(request.server_auth_code)
        
        if not token_result['success']:
            return token_result
        
        token_data = token_result['data']
        id_token = token_data.get('id_token')
        
        if not id_token:
            raise HTTPException(
                status_code=400,
                detail=ResponseFormatter.error("未获取到id_token", "no_id_token", 400)
            )
        
        # 第二步：验证idToken并提取用户信息
        verify_result = huawei_auth.verify_id_token_and_get_user_info(id_token)
        
        if verify_result['success']:
            # 合并token信息和用户信息
            combined_result = {
                'token_info': token_data,
                'user_info': verify_result['data']['user_info'],
                'token_valid': True,
                'verification_method': 'server_auth_code'
            }
            
            return ResponseFormatter.success(combined_result, "使用serverAuthCode验证成功")
        else:
            return verify_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"验证serverAuthCode接口异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500)
        )

@app.post("/get_user_info_by_access_token")
async def get_user_info_by_access_token(request: AccessTokenRequest):
    """
    使用access_token获取用户信息（包含OpenID和UnionID）
    """
    try:
        # 使用access_token获取用户信息
        result = huawei_auth.get_user_info_by_access_token(request.access_token)
        
        return result
        
    except Exception as e:
        logger.error(f"获取用户信息接口异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500)
        )

@app.get("/")
async def health_check():
    """健康检查端点"""
    return {
        'status': 'ok',
        'message': '华为认证服务器运行正常',
        'version': '1.0.0'
    }

@app.post("/api/agc/verify-token")
async def verify_agc_token(request: AGCTokenRequest):
    """
    验证AGConnect访问令牌
    使用华为AGC官方验证接口
    """
    try:
        # 调用华为AGC token验证服务
        result = huawei_auth.verify_agc_token(request.access_token)
        
        if result['success']:
            logger.info("AGC Token验证成功")
            return result
        else:
            logger.warning(f"AGC Token验证失败: {result.get('error', 'Unknown error')}")
            raise HTTPException(status_code=401, detail=result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AGC Token验证异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                'success': False,
                'error': f'服务器内部错误: {str(e)}'
            }
        )

@app.post("/api/huawei/token")
async def get_token(request: TokenRequest):
    """
    通过授权码获取访问令牌
    对应Java Demo中的TokenAPIDemo功能
    """
    try:
        logger.info(f"获取Token请求: code={request.code[:10]}..., redirect_uri={request.redirect_uri}")
        
        # 调用华为认证服务
        result = huawei_auth.get_token_by_code(request.code, request.redirect_uri, request.grant_type)
        
        if result['success']:
            logger.info("Token获取成功")
            return result
        else:
            logger.error(f"Token获取失败: {result['error']}")
            status_code = result.get('status_code', 400)
            raise HTTPException(status_code=status_code, detail=result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取Token异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                'success': False,
                'error': f'服务器内部错误: {str(e)}'
            }
        )

@app.post("/api/huawei/tokeninfo")
async def get_token_info(request: TokenInfoRequest):
    """
    获取访问令牌信息
    对应Java Demo中的GetTokenInfoAPIDemo功能
    """
    try:
        logger.info(f"获取Token信息请求: access_token={request.access_token[:20]}...")
        
        # 调用华为认证服务
        result = huawei_auth.get_token_info(request.access_token)
        
        if result['success']:
            logger.info("Token信息获取成功")
            return result
        else:
            logger.error(f"Token信息获取失败: {result['error']}")
            status_code = result.get('status_code', 400)
            raise HTTPException(status_code=status_code, detail=result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取Token信息异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                'success': False,
                'error': f'服务器内部错误: {str(e)}'
            }
        )

@app.post("/api/huawei/verify-idtoken")
async def verify_id_token_api(request: IdTokenRequest):
    """
    验证ID Token
    对应Java Demo中的IDTokenParser功能
    """
    try:
        logger.info(f"验证ID Token请求: id_token={request.id_token[:50]}...")
        
        # 调用华为认证服务
        result = huawei_auth.verify_id_token(request.id_token)
        
        if result['success']:
            logger.info("ID Token验证成功")
            return result
        else:
            logger.error(f"ID Token验证失败: {result['error']}")
            raise HTTPException(status_code=400, detail=result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"验证ID Token异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                'success': False,
                'error': f'服务器内部错误: {str(e)}'
            }
        )

@app.get("/api/huawei/config")
async def get_config():
    """获取当前配置信息（不包含敏感信息）"""
    try:
        return {
            'success': True,
            'data': {
                'client_id': Config.HUAWEI_CLIENT_ID,
                'project_id': Config.HUAWEI_PROJECT_ID,
                'token_url': Config.HUAWEI_TOKEN_URL,
                'tokeninfo_url': Config.HUAWEI_TOKENINFO_URL,
                'certs_url': Config.HUAWEI_CERTS_URL,
                'issuer': Config.HUAWEI_ISSUER
            }
        }
    except Exception as e:
        logger.error(f"获取配置异常: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                'success': False,
                'error': f'服务器内部错误: {str(e)}'
            }
        )

# 全局异常处理器
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """404错误处理"""
    return JSONResponse(
        status_code=404,
        content={
            'success': False,
            'error': '接口不存在'
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """500错误处理"""
    logger.error(f"服务器内部错误: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            'success': False,
            'error': '服务器内部错误'
        }
    )

if __name__ == '__main__':
    try:
        # 验证配置
        Config.validate_config()
        logger.info("配置验证通过")
        
        # 启动服务器
        logger.info(f"启动华为认证服务器: {Config.HOST}:{Config.PORT}")
        uvicorn.run(
            "app:app",
            host=Config.HOST,
            port=Config.PORT,
            reload=Config.FASTAPI_DEBUG,
            log_level="info"
        )
        
    except ValueError as e:
        logger.error(f"配置错误: {e}")
        print(f"配置错误: {e}")
        print("请检查.env文件或环境变量配置")
    except Exception as e:
        logger.error(f"启动服务器失败: {e}")
        print(f"启动服务器失败: {e}")