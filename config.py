import os
import json
from typing import Dict, Any

class Config:
    """配置管理类"""
    
    # 华为AGC配置 - 直接在代码中设置
    HUAWEI_CLIENT_ID = '115371953'
    HUAWEI_CLIENT_SECRET = '418a82489888387ead26ca6f675b1287a705c31d627e5e0cd06859733e5fb089'
    HUAWEI_PROJECT_ID = '461323198430484375'
    HUAWEI_DEVELOPER_ID = '10086000833406187'
    
    # 服务器配置
    FASTAPI_ENV = os.environ.get('FASTAPI_ENV', 'production')
    FASTAPI_DEBUG = os.environ.get('FASTAPI_DEBUG', 'False').lower() == 'true'
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5000))
    
    # 华为OAuth相关URL
    HUAWEI_TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token'
    HUAWEI_TOKENINFO_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo'
    HUAWEI_AGC_TOKENINFO_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo'  # AGC Token验证接口
    HUAWEI_CERTS_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/certs'
    HUAWEI_ISSUER = 'https://accounts.huawei.com'  # 修改为正确的issuer
    HUAWEI_USERINFO_ENDPOINT = 'https://oauth-api.cloud.huawei.com/rest.php?nsp_svc=huawei.oauth2.user.getTokenInfo'  # 用户信息接口
    
    @classmethod
    def validate_config(cls):
        """验证配置完整性"""
        required_fields = [
            'HUAWEI_CLIENT_ID',
            'HUAWEI_CLIENT_SECRET', 
            'HUAWEI_PROJECT_ID',
            'HUAWEI_DEVELOPER_ID'
        ]
        
        missing_fields = []
        for field in required_fields:
            value = getattr(cls, field, None)
            if not value:
                missing_fields.append(field)
        
        if missing_fields:
            raise ValueError(f"缺少必需的配置项: {', '.join(missing_fields)}")
        
        return True