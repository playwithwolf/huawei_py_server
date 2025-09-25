#!/usr/bin/env python3
"""
华为认证服务器测试脚本
用于测试各个API端点的功能
"""

import requests
import json
import sys

# 服务器配置
BASE_URL = "http://localhost:5000"

def test_health_check():
    """测试健康检查接口"""
    print("🔍 测试健康检查接口...")
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ 健康检查失败: {e}")
        return False

def test_config_endpoint():
    """测试配置信息接口"""
    print("\n🔍 测试配置信息接口...")
    try:
        response = requests.get(f"{BASE_URL}/api/huawei/config")
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ 配置信息获取失败: {e}")
        return False

def test_token_endpoint():
    """测试获取Token接口"""
    print("\n🔍 测试获取Token接口...")
    
    # 测试缺少参数的情况
    print("测试缺少参数...")
    try:
        response = requests.post(f"{BASE_URL}/api/huawei/token", json={})
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")
    
    # 测试无效授权码的情况
    print("\n测试无效授权码...")
    try:
        data = {
            "code": "invalid_code_for_testing",
            "redirect_uri": "https://example.com/callback",
            "grant_type": "authorization_code"
        }
        response = requests.post(f"{BASE_URL}/api/huawei/token", json=data)
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")

def test_token_info_endpoint():
    """测试获取Token信息接口"""
    print("\n🔍 测试获取Token信息接口...")
    
    # 测试缺少参数的情况
    print("测试缺少参数...")
    try:
        response = requests.post(f"{BASE_URL}/api/huawei/tokeninfo", json={})
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")
    
    # 测试无效Token的情况
    print("\n测试无效Token...")
    try:
        data = {
            "access_token": "invalid_token_for_testing"
        }
        response = requests.post(f"{BASE_URL}/api/huawei/tokeninfo", json=data)
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")

def test_verify_id_token_endpoint():
    """测试验证ID Token接口"""
    print("\n🔍 测试验证ID Token接口...")
    
    # 测试缺少参数的情况
    print("测试缺少参数...")
    try:
        response = requests.post(f"{BASE_URL}/api/huawei/verify-idtoken", json={})
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")
    
    # 测试无效ID Token的情况
    print("\n测试无效ID Token...")
    try:
        data = {
            "id_token": "invalid_id_token_for_testing"
        }
        response = requests.post(f"{BASE_URL}/api/huawei/verify-idtoken", json=data)
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")

def test_404_endpoint():
    """测试404错误处理"""
    print("\n🔍 测试404错误处理...")
    try:
        response = requests.get(f"{BASE_URL}/api/nonexistent")
        print(f"状态码: {response.status_code}")
        print(f"响应: {json.dumps(response.json(), ensure_ascii=False, indent=2)}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")

def main():
    """主测试函数"""
    print("🚀 开始测试华为认证服务器...")
    print(f"服务器地址: {BASE_URL}")
    print("=" * 50)
    
    # 检查服务器是否运行
    if not test_health_check():
        print("❌ 服务器未运行，请先启动服务器: python app.py")
        sys.exit(1)
    
    print("✅ 服务器运行正常")
    
    # 运行各项测试
    test_config_endpoint()
    test_token_endpoint()
    test_token_info_endpoint()
    test_verify_id_token_endpoint()
    test_404_endpoint()
    
    print("\n" + "=" * 50)
    print("🎉 测试完成！")
    print("\n📝 说明:")
    print("- 以上测试主要验证API接口的参数验证和错误处理")
    print("- 要测试真实的华为认证流程，需要有效的授权码和Token")
    print("- 可以通过华为开发者控制台获取测试用的授权码")

if __name__ == "__main__":
    main()