import requests
import jwt
import json
import time
from typing import Dict, Optional, Any
from urllib.parse import urlencode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from config import Config
from utils import Logger, HuaweiAuthError, ResponseFormatter, handle_exceptions

class HuaweiAuthService:
    """华为认证服务类"""
    
    def __init__(self):
        self.config = Config()
        self._public_keys_cache = {}
        self._cache_expiry = 0
        self.logger = Logger.setup_logger(__name__)
        
    @handle_exceptions(Logger.setup_logger(__name__))
    def exchange_id_token_by_server_auth_code(self, server_auth_code: str) -> Dict[str, Any]:
        """
        使用serverAuthCode换取idToken
        根据华为验证服务器demo.txt中的说明实现
        """
        try:
            self.logger.info(f"开始使用serverAuthCode换取idToken: code={server_auth_code[:10]}...")
            
            # 构建请求参数
            data = {
                'grant_type': 'authorization_code',
                'client_id': Config.HUAWEI_CLIENT_ID,
                'client_secret': Config.HUAWEI_CLIENT_SECRET,
                'code': server_auth_code
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # 发送请求到华为OAuth接口
            response = requests.post(Config.HUAWEI_TOKEN_URL, data=data, headers=headers, timeout=30)
            
            self.logger.info(f"换取idToken请求响应状态: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info("成功换取idToken")
                
                return ResponseFormatter.success({
                    'id_token': result.get('id_token'),
                    'access_token': result.get('access_token'),
                    'expires_in': result.get('expires_in'),
                    'token_type': result.get('token_type', 'Bearer'),
                    'refresh_token': result.get('refresh_token')
                }, "成功换取idToken")
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('error_description', f'HTTP {response.status_code}')
                self.logger.error(f"换取idToken失败: {error_msg}")
                
                return ResponseFormatter.error(
                    f"换取idToken失败: {error_msg}",
                    error_data.get('error', 'token_exchange_failed'),
                    response.status_code
                )
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"网络请求异常: {str(e)}")
            return ResponseFormatter.error(f"网络请求异常: {str(e)}", "network_error", 500)
        except Exception as e:
            self.logger.error(f"换取idToken异常: {str(e)}")
            return ResponseFormatter.error(f"换取idToken异常: {str(e)}", "internal_error", 500)
        
    def get_token_by_code(self, code: str, redirect_uri: str, grant_type: str = "authorization_code") -> Dict[str, Any]:
        """
        通过授权码获取访问令牌
        对应Java Demo中的TokenAPIDemo.getTokenByCode方法
        """
        try:
            self.logger.info(f"开始获取Token: code={code[:10]}..., redirect_uri={redirect_uri}")
            
            # 构建请求参数
            data = {
                'grant_type': grant_type,
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': Config.HUAWEI_CLIENT_ID,
                'client_secret': Config.HUAWEI_CLIENT_SECRET
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # 发送请求
            response = requests.post(Config.HUAWEI_TOKEN_URL, data=data, headers=headers, timeout=30)
            
            self.logger.info(f"Token请求响应状态: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info("Token获取成功")
                return ResponseFormatter.success(result, "Token获取成功")
            else:
                error_msg = f"获取Token失败: HTTP {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f", 详情: {error_detail}"
                    self.logger.error(f"Token获取失败: {error_detail}")
                except:
                    error_msg += f", 响应: {response.text}"
                    self.logger.error(f"Token获取失败: {response.text}")
                
                raise HuaweiAuthError(error_msg, "TOKEN_REQUEST_FAILED", response.status_code)
                
        except requests.exceptions.Timeout:
            raise HuaweiAuthError("请求超时", "REQUEST_TIMEOUT", 408)
        except requests.exceptions.RequestException as e:
            raise HuaweiAuthError(f"网络请求失败: {str(e)}", "NETWORK_ERROR", 503)
        except Exception as e:
            self.logger.error(f"获取Token异常: {str(e)}")
            raise
    
    def verify_agc_token(self, access_token: str) -> Dict[str, Any]:
        """
        验证AGConnect访问令牌
        使用华为AGC官方验证接口: https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo
        """
        try:
            self.logger.info(f"开始验证AGC Token: {access_token[:20]}...")
            
            # 构建请求参数
            params = {
                'access_token': access_token
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'HuaweiPythonServer/1.0'
            }
            
            # 发送请求到华为AGC验证接口
            response = requests.get(
                Config.HUAWEI_AGC_TOKENINFO_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            
            self.logger.info(f"AGC Token验证响应状态: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                # 检查token是否有效
                if 'error' in result:
                    self.logger.warning(f"AGC Token无效: {result}")
                    return ResponseFormatter.error(
                        f"Token验证失败: {result.get('error_description', result.get('error', 'Unknown error'))}",
                        "INVALID_TOKEN"
                    )
                
                # Token有效，返回用户信息
                self.logger.info("AGC Token验证成功")
                return ResponseFormatter.success(result, "Token验证成功")
                
            elif response.status_code == 400:
                # Token无效或过期
                try:
                    error_detail = response.json()
                    error_msg = error_detail.get('error_description', error_detail.get('error', 'Invalid token'))
                except:
                    error_msg = "Invalid token"
                
                self.logger.warning(f"AGC Token无效: {error_msg}")
                return ResponseFormatter.error(f"Token无效: {error_msg}", "INVALID_TOKEN")
                
            else:
                error_msg = f"AGC验证服务异常: HTTP {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f", 详情: {error_detail}"
                except:
                    error_msg += f", 响应: {response.text}"
                
                self.logger.error(error_msg)
                raise HuaweiAuthError(error_msg, "AGC_SERVICE_ERROR", response.status_code)
                
        except requests.exceptions.Timeout:
            raise HuaweiAuthError("AGC验证请求超时", "REQUEST_TIMEOUT", 408)
        except requests.exceptions.RequestException as e:
            raise HuaweiAuthError(f"AGC验证网络请求失败: {str(e)}", "NETWORK_ERROR", 503)
        except Exception as e:
            self.logger.error(f"AGC Token验证异常: {str(e)}")
            raise

    def get_token_info(self, access_token: str) -> Dict[str, Any]:
        """
        获取访问令牌信息
        对应Java Demo中的GetTokenInfoAPIDemo.getClientTokenInfo方法
        """
        try:
            data = {
                'nsp_svc': 'OpenUP.User.getInfo',
                'access_token': access_token
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'HuaweiPythonServer/1.0'
            }
            
            response = requests.post(
                self.config.HUAWEI_TOKENINFO_URL,
                data=urlencode(data),
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'data': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}: {response.text}',
                    'status_code': response.status_code
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'请求异常: {str(e)}'
            }
    
    def verify_id_token_and_get_user_info(self, id_token: str) -> Dict[str, Any]:
        """
        验证idToken并提取OpenID和UnionID
        根据华为验证服务器demo.txt中的说明实现
        """
        try:
            self.logger.info("开始验证idToken并提取用户信息")
            
            # 首先验证idToken的有效性
            verify_result = self.verify_id_token(id_token)
            
            if not verify_result['success']:
                self.logger.error(f"idToken验证失败: {verify_result['error']}")
                return ResponseFormatter.error(
                    f"idToken验证失败: {verify_result['error']}", 
                    "invalid_id_token", 
                    400
                )
            
            # 从验证结果中提取用户信息
            decoded_token = verify_result['data']
            
            # 提取关键用户信息
            user_info = {
                'openId': decoded_token.get('sub'),  # OpenID存储在sub字段
                'unionId': decoded_token.get('union_id'),  # UnionID字段
                'email': decoded_token.get('email'),
                'name': decoded_token.get('name'),
                'picture': decoded_token.get('picture'),
                'aud': decoded_token.get('aud'),  # 应用ID
                'iss': decoded_token.get('iss'),  # 发行者
                'exp': decoded_token.get('exp'),  # 过期时间
                'iat': decoded_token.get('iat'),  # 签发时间
            }
            
            self.logger.info(f"成功提取用户信息: OpenID={user_info.get('openId')}, UnionID={user_info.get('unionId')}")
            
            return ResponseFormatter.success({
                'user_info': user_info,
                'token_valid': True,
                'decoded_token': decoded_token
            }, "idToken验证成功并提取用户信息")
            
        except Exception as e:
            self.logger.error(f"验证idToken并提取用户信息异常: {str(e)}")
            return ResponseFormatter.error(f"验证异常: {str(e)}", "internal_error", 500)
    
    def get_user_info_by_access_token(self, access_token: str) -> Dict[str, Any]:
        """
        使用access_token获取用户信息（包含OpenID和UnionID）
        根据华为验证服务器demo.txt中的说明实现
        """
        try:
            self.logger.info("开始使用access_token获取用户信息")
            
            # 华为获取用户信息的接口
            url = "https://account.cloud.huawei.com/rest.php?nsp_svc=GOpen.User.getInfo"
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            self.logger.info(f"获取用户信息请求响应状态: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info("成功获取用户信息")
                
                # 提取关键信息
                user_info = {
                    'openId': result.get('openID'),
                    'unionId': result.get('unionID'),
                    'displayName': result.get('displayName'),
                    'email': result.get('email'),
                    'headPictureURL': result.get('headPictureURL'),
                    'gender': result.get('gender'),
                    'countryCode': result.get('countryCode')
                }
                
                return ResponseFormatter.success({
                    'user_info': user_info,
                    'raw_response': result
                }, "成功获取用户信息")
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('error_description', f'HTTP {response.status_code}')
                
                # 处理特定错误码
                if response.status_code == 401 or error_data.get('error_code') in ['31204', '6']:
                    error_msg = "access_token无效，需重新获取"
                elif error_data.get('error_code') == '60180004':
                    error_msg = "access_token已过期"
                
                self.logger.error(f"获取用户信息失败: {error_msg}")
                
                return ResponseFormatter.error(
                    f"获取用户信息失败: {error_msg}",
                    error_data.get('error', 'get_user_info_failed'),
                    response.status_code
                )
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"网络请求异常: {str(e)}")
            return ResponseFormatter.error(f"网络请求异常: {str(e)}", "network_error", 500)
        except Exception as e:
            self.logger.error(f"获取用户信息异常: {str(e)}")
            return ResponseFormatter.error(f"获取用户信息异常: {str(e)}", "internal_error", 500)

    def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        验证ID Token
        对应Java Demo中的IDTokenParser.verify方法
        """
        try:
            # 解码JWT头部获取kid
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header.get('kid')
            
            if not kid:
                return {
                    'success': False,
                    'error': 'ID Token缺少kid字段'
                }
            
            # 获取公钥
            public_key = self._get_public_key_by_kid(kid)
            if not public_key:
                return {
                    'success': False,
                    'error': f'无法获取kid为{kid}的公钥'
                }
            
            # 验证JWT
            decoded_token = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256'],
                issuer=self.config.HUAWEI_ISSUER,
                audience=self.config.HUAWEI_CLIENT_ID,
                options={
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True
                }
            )
            
            return {
                'success': True,
                'data': decoded_token
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'success': False,
                'error': 'ID Token已过期'
            }
        except jwt.InvalidTokenError as e:
            return {
                'success': False,
                'error': f'ID Token无效: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'验证异常: {str(e)}'
            }
    
    def _get_public_key_by_kid(self, kid: str) -> Optional[Any]:
        """
        根据kid获取公钥
        对应Java Demo中的IDTokenParser.getRSAPublicKeyByKid方法
        """
        # 检查缓存是否过期
        current_time = time.time()
        if current_time > self._cache_expiry:
            self._refresh_public_keys()
        
        return self._public_keys_cache.get(kid)
    
    def _refresh_public_keys(self):
        """
        刷新公钥缓存
        对应Java Demo中的IDTokenParser.getJwks方法
        """
        try:
            response = requests.get(self.config.HUAWEI_CERTS_URL, timeout=30)
            if response.status_code == 200:
                jwks_data = response.json()
                keys = jwks_data.get('keys', [])
                
                self._public_keys_cache.clear()
                
                for key_data in keys:
                    kid = key_data.get('kid')
                    if kid:
                        public_key = self._jwk_to_rsa_public_key(key_data)
                        if public_key:
                            self._public_keys_cache[kid] = public_key
                
                # 设置缓存过期时间（1小时）
                self._cache_expiry = time.time() + 3600
                
        except Exception as e:
            print(f"刷新公钥缓存失败: {e}")
    
    def _jwk_to_rsa_public_key(self, jwk_data: Dict[str, Any]) -> Optional[Any]:
        """
        将JWK格式转换为RSA公钥
        对应Java Demo中的IDTokenParser.getRsaPublicKeyByJwk方法
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # 获取n和e参数
            n_bytes = base64.urlsafe_b64decode(jwk_data['n'] + '==')
            e_bytes = base64.urlsafe_b64decode(jwk_data['e'] + '==')
            
            # 转换为整数
            n = int.from_bytes(n_bytes, 'big')
            e = int.from_bytes(e_bytes, 'big')
            
            # 创建RSA公钥
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(default_backend())
            
            return public_key
            
        except Exception as e:
            print(f"JWK转换RSA公钥失败: {e}")
            return None