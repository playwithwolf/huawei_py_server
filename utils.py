import logging
import json
import traceback
from functools import wraps
from datetime import datetime
from typing import Dict, Any, Optional

class HuaweiAuthError(Exception):
    """华为认证相关错误"""
    def __init__(self, message: str, error_code: str = None, status_code: int = 400):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)

class Logger:
    """日志管理器"""
    
    @staticmethod
    def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """设置日志记录器"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # 避免重复添加处理器
        if not logger.handlers:
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            
            # 文件处理器
            file_handler = logging.FileHandler('huawei_auth.log', encoding='utf-8')
            file_handler.setLevel(level)
            
            # 格式化器
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            
            logger.addHandler(console_handler)
            logger.addHandler(file_handler)
        
        return logger

class ResponseFormatter:
    """响应格式化器"""
    
    @staticmethod
    def success(data: Any = None, message: str = "操作成功") -> Dict[str, Any]:
        """成功响应格式"""
        response = {
            'success': True,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        if data is not None:
            response['data'] = data
        return response
    
    @staticmethod
    def error(message: str, error_code: str = None, status_code: int = 400, details: Any = None) -> Dict[str, Any]:
        """错误响应格式"""
        response = {
            'success': False,
            'error': message,
            'timestamp': datetime.now().isoformat(),
            'status_code': status_code
        }
        if error_code:
            response['error_code'] = error_code
        if details:
            response['details'] = details
        return response

def handle_exceptions(logger: logging.Logger):
    """异常处理装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except HuaweiAuthError as e:
                logger.error(f"华为认证错误 in {func.__name__}: {e.message}")
                return ResponseFormatter.error(
                    message=e.message,
                    error_code=e.error_code,
                    status_code=e.status_code
                )
            except Exception as e:
                logger.error(f"未预期错误 in {func.__name__}: {str(e)}")
                logger.error(f"错误堆栈: {traceback.format_exc()}")
                return ResponseFormatter.error(
                    message="服务器内部错误",
                    error_code="INTERNAL_ERROR",
                    status_code=500,
                    details=str(e) if logger.level <= logging.DEBUG else None
                )
        return wrapper
    return decorator

def validate_request_data(required_fields: list, optional_fields: list = None):
    """请求数据验证装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request
            
            data = request.get_json()
            if not data:
                return ResponseFormatter.error("请求体不能为空"), 400
            
            # 检查必需字段
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return ResponseFormatter.error(
                    f"缺少必需参数: {', '.join(missing_fields)}",
                    error_code="MISSING_REQUIRED_FIELDS"
                ), 400
            
            # 过滤允许的字段
            allowed_fields = required_fields + (optional_fields or [])
            filtered_data = {k: v for k, v in data.items() if k in allowed_fields}
            
            # 将过滤后的数据传递给函数
            kwargs['validated_data'] = filtered_data
            return func(*args, **kwargs)
        return wrapper
    return decorator

class RequestValidator:
    """请求验证器"""
    
    @staticmethod
    def validate_token_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """验证获取Token请求"""
        required_fields = ['code', 'redirect_uri']
        optional_fields = ['grant_type', 'state']
        
        errors = []
        
        # 检查必需字段
        for field in required_fields:
            if not data.get(field):
                errors.append(f"缺少必需参数: {field}")
            elif not isinstance(data[field], str) or not data[field].strip():
                errors.append(f"参数 {field} 必须是非空字符串")
        
        # 验证grant_type
        if data.get('grant_type') and data['grant_type'] not in ['authorization_code', 'refresh_token']:
            errors.append("grant_type 必须是 'authorization_code' 或 'refresh_token'")
        
        if errors:
            raise HuaweiAuthError("; ".join(errors), "INVALID_REQUEST_DATA")
        
        return {
            'code': data['code'].strip(),
            'redirect_uri': data['redirect_uri'].strip(),
            'grant_type': data.get('grant_type', 'authorization_code').strip(),
            'state': data.get('state', '').strip()
        }
    
    @staticmethod
    def validate_token_info_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """验证获取Token信息请求"""
        if not data.get('access_token'):
            raise HuaweiAuthError("缺少access_token参数", "MISSING_ACCESS_TOKEN")
        
        if not isinstance(data['access_token'], str) or not data['access_token'].strip():
            raise HuaweiAuthError("access_token必须是非空字符串", "INVALID_ACCESS_TOKEN")
        
        return {
            'access_token': data['access_token'].strip()
        }
    
    @staticmethod
    def validate_id_token_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """验证ID Token请求"""
        if not data.get('id_token'):
            raise HuaweiAuthError("缺少id_token参数", "MISSING_ID_TOKEN")
        
        if not isinstance(data['id_token'], str) or not data['id_token'].strip():
            raise HuaweiAuthError("id_token必须是非空字符串", "INVALID_ID_TOKEN")
        
        return {
            'id_token': data['id_token'].strip()
        }

def log_request_response(logger: logging.Logger):
    """请求响应日志装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request
            
            # 记录请求
            logger.info(f"请求 {func.__name__}: {request.method} {request.path}")
            if request.is_json:
                # 不记录敏感信息
                safe_data = {}
                for key, value in request.get_json().items():
                    if key in ['access_token', 'id_token', 'code']:
                        safe_data[key] = f"{str(value)[:10]}..." if value else None
                    else:
                        safe_data[key] = value
                logger.debug(f"请求数据: {json.dumps(safe_data, ensure_ascii=False)}")
            
            # 执行函数
            start_time = datetime.now()
            result = func(*args, **kwargs)
            end_time = datetime.now()
            
            # 记录响应
            duration = (end_time - start_time).total_seconds()
            logger.info(f"响应 {func.__name__}: 耗时 {duration:.3f}s")
            
            return result
        return wrapper
    return decorator