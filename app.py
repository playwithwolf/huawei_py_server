from flask import Flask, request, jsonify
import logging
import os
from config import Config
from huawei_auth import HuaweiAuthService

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)

# 初始化华为认证服务
huawei_auth = HuaweiAuthService()

@app.route('/verify_id_token', methods=['POST'])
def verify_id_token():
    """
    直接使用idToken验证OpenID和UnionID的有效性
    """
    try:
        data = request.get_json()
        if not data or 'id_token' not in data:
            return jsonify(ResponseFormatter.error("缺少id_token参数", "missing_parameter", 400))
        
        id_token = data['id_token']
        
        # 验证idToken并提取用户信息
        result = huawei_auth.verify_id_token_and_get_user_info(id_token)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"验证idToken接口异常: {str(e)}")
        return jsonify(ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500))

@app.route('/verify_server_auth_code', methods=['POST'])
def verify_server_auth_code():
    """
    使用serverAuthCode换取idToken后再验证OpenID和UnionID的有效性
    """
    try:
        data = request.get_json()
        if not data or 'server_auth_code' not in data:
            return jsonify(ResponseFormatter.error("缺少server_auth_code参数", "missing_parameter", 400))
        
        server_auth_code = data['server_auth_code']
        
        # 第一步：使用serverAuthCode换取access_token和id_token
        token_result = huawei_auth.exchange_id_token_by_server_auth_code(server_auth_code)
        
        if not token_result['success']:
            return jsonify(token_result)
        
        token_data = token_result['data']
        id_token = token_data.get('id_token')
        
        if not id_token:
            return jsonify(ResponseFormatter.error("未获取到id_token", "no_id_token", 400))
        
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
            
            return jsonify(ResponseFormatter.success(combined_result, "使用serverAuthCode验证成功"))
        else:
            return jsonify(verify_result)
        
    except Exception as e:
        logger.error(f"验证serverAuthCode接口异常: {str(e)}")
        return jsonify(ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500))

@app.route('/get_user_info_by_access_token', methods=['POST'])
def get_user_info_by_access_token():
    """
    使用access_token获取用户信息（包含OpenID和UnionID）
    """
    try:
        data = request.get_json()
        if not data or 'access_token' not in data:
            return jsonify(ResponseFormatter.error("缺少access_token参数", "missing_parameter", 400))
        
        access_token = data['access_token']
        
        # 使用access_token获取用户信息
        result = huawei_auth.get_user_info_by_access_token(access_token)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"获取用户信息接口异常: {str(e)}")
        return jsonify(ResponseFormatter.error(f"服务器内部错误: {str(e)}", "internal_error", 500))

@app.route('/', methods=['GET'])
def health_check():
    """健康检查端点"""
    return jsonify({
        'status': 'ok',
        'message': '华为认证服务器运行正常',
        'version': '1.0.0'
    })

@app.route('/api/agc/verify-token', methods=['POST'])
def verify_agc_token():
    """
    验证AGConnect访问令牌
    使用华为AGC官方验证接口
    """
    try:
        data = request.get_json()
        
        # 验证必需参数
        if not data or not data.get('access_token'):
            return jsonify({
                'success': False,
                'error': '缺少access_token参数'
            }), 400
        
        access_token = data['access_token']
        
        # 调用华为AGC token验证服务
        result = huawei_auth.verify_agc_token(access_token)
        
        if result['success']:
            logger.info("AGC Token验证成功")
            return jsonify(result)
        else:
            logger.warning(f"AGC Token验证失败: {result.get('error', 'Unknown error')}")
            return jsonify(result), 401
            
    except Exception as e:
        logger.error(f"AGC Token验证异常: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}'
        }), 500

@app.route('/api/huawei/token', methods=['POST'])
def get_token():
    """
    通过授权码获取访问令牌
    对应Java Demo中的TokenAPIDemo功能
    """
    try:
        data = request.get_json()
        
        # 验证必需参数
        required_fields = ['code', 'redirect_uri']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'缺少必需参数: {", ".join(missing_fields)}'
            }), 400
        
        code = data['code']
        redirect_uri = data['redirect_uri']
        grant_type = data.get('grant_type', 'authorization_code')
        
        logger.info(f"获取Token请求: code={code[:10]}..., redirect_uri={redirect_uri}")
        
        # 调用华为认证服务
        result = huawei_auth.get_token_by_code(code, redirect_uri, grant_type)
        
        if result['success']:
            logger.info("Token获取成功")
            return jsonify(result), 200
        else:
            logger.error(f"Token获取失败: {result['error']}")
            status_code = result.get('status_code', 400)
            return jsonify(result), status_code
            
    except Exception as e:
        logger.error(f"获取Token异常: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}'
        }), 500

@app.route('/api/huawei/tokeninfo', methods=['POST'])
def get_token_info():
    """
    获取访问令牌信息
    对应Java Demo中的GetTokenInfoAPIDemo功能
    """
    try:
        data = request.get_json()
        
        # 验证必需参数
        if not data.get('access_token'):
            return jsonify({
                'success': False,
                'error': '缺少access_token参数'
            }), 400
        
        access_token = data['access_token']
        
        logger.info(f"获取Token信息请求: access_token={access_token[:20]}...")
        
        # 调用华为认证服务
        result = huawei_auth.get_token_info(access_token)
        
        if result['success']:
            logger.info("Token信息获取成功")
            return jsonify(result), 200
        else:
            logger.error(f"Token信息获取失败: {result['error']}")
            status_code = result.get('status_code', 400)
            return jsonify(result), status_code
            
    except Exception as e:
        logger.error(f"获取Token信息异常: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}'
        }), 500

@app.route('/api/huawei/verify-idtoken', methods=['POST'])
def verify_id_token_api():
    """
    验证ID Token
    对应Java Demo中的IDTokenParser功能
    """
    try:
        data = request.get_json()
        
        # 验证必需参数
        if not data.get('id_token'):
            return jsonify({
                'success': False,
                'error': '缺少id_token参数'
            }), 400
        
        id_token = data['id_token']
        
        logger.info(f"验证ID Token请求: id_token={id_token[:50]}...")
        
        # 调用华为认证服务
        result = huawei_auth.verify_id_token(id_token)
        
        if result['success']:
            logger.info("ID Token验证成功")
            return jsonify(result), 200
        else:
            logger.error(f"ID Token验证失败: {result['error']}")
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"验证ID Token异常: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}'
        }), 500

@app.route('/api/huawei/config', methods=['GET'])
def get_config():
    """获取当前配置信息（不包含敏感信息）"""
    try:
        return jsonify({
            'success': True,
            'data': {
                'client_id': Config.HUAWEI_CLIENT_ID,
                'project_id': Config.HUAWEI_PROJECT_ID,
                'token_url': Config.HUAWEI_TOKEN_URL,
                'tokeninfo_url': Config.HUAWEI_TOKENINFO_URL,
                'certs_url': Config.HUAWEI_CERTS_URL,
                'issuer': Config.HUAWEI_ISSUER
            }
        }), 200
    except Exception as e:
        logger.error(f"获取配置异常: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({
        'success': False,
        'error': '接口不存在'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    logger.error(f"服务器内部错误: {str(error)}")
    return jsonify({
        'success': False,
        'error': '服务器内部错误'
    }), 500

if __name__ == '__main__':
    try:
        # 验证配置
        Config.validate_config()
        logger.info("配置验证通过")
        
        # 启动服务器
        logger.info(f"启动华为认证服务器: {Config.HOST}:{Config.PORT}")
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.FLASK_DEBUG,
            use_reloader=False
        )
        
    except ValueError as e:
        logger.error(f"配置错误: {e}")
        print(f"配置错误: {e}")
        print("请检查.env文件或环境变量配置")
    except Exception as e:
        logger.error(f"启动服务器失败: {e}")
        print(f"启动服务器失败: {e}")