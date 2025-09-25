import os
import json
from typing import Dict, Any

class Config:
    """配置管理类"""
    
    # 华为AGC配置 - 直接在代码中设置
    HUAWEI_CLIENT_ID = '107917734'
    HUAWEI_CLIENT_SECRET = 'f462eeae4f5642a0a91d6edc9b1d64c6'
    HUAWEI_PROJECT_ID = '99536292104595456'
    HUAWEI_DEVELOPER_ID = '1781922428767748032'
    
    # 服务器配置
    FLASK_ENV = 'development'
    FLASK_DEBUG = True
    HOST = '0.0.0.0'
    PORT = 5000
    
    # 华为OAuth相关URL
    HUAWEI_TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token'
    HUAWEI_TOKENINFO_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo'
    HUAWEI_AGC_TOKENINFO_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/tokeninfo'  # AGC Token验证接口
    HUAWEI_CERTS_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/certs'
    HUAWEI_ISSUER = 'https://oauth-login.cloud.huawei.com'
    
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