# auth_server_flask/auth_utils.py

import uuid
import jwt
from datetime import datetime, timedelta, timezone

def generate_oauth_state_parameter():
    """OAuth 2.0のCSRF対策用のstateパラメータを生成します。"""
    return str(uuid.uuid4())

def create_custom_jwt(user_email, user_name, issuer_url, audience_url, jwt_secret_key, expires_delta_hours=1):
    """
    ユーザー情報と設定に基づいてカスタムJWTを生成します。

    Args:
        user_email (str): ユーザーのメールアドレス (JWTのsubおよびemailクレーム)。
        user_name (str): ユーザー名 (JWTのnameクレーム)。
        issuer_url (str): JWTの発行者URL (issクレーム)。
        audience_url (str): JWTの対象者URL (audクレーム)。
        jwt_secret_key (str): JWTの署名に使用する秘密鍵。
        expires_delta_hours (int, optional): JWTの有効期間（時間）。デフォルトは1時間。

    Returns:
        str: 生成されたJWT文字列。

    Raises:
        Exception: JWTエンコード中にエラーが発生した場合。
    """
    payload = {
        "sub": user_email,
        "name": user_name,
        "email": user_email,
        "iss": issuer_url,
        "aud": audience_url,
        "exp": datetime.now(timezone.utc) + timedelta(hours=expires_delta_hours),
        "iat": datetime.now(timezone.utc)
    }
    try:
        token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
        print(f"DEBUG auth_utils: JWT generated for {user_email}. Token (first 20 chars): {token[:20]}...")
        return token
    except Exception as e:
        print(f"ERROR auth_utils: JWT encoding failed: {e}")
        raise # エラーを呼び出し元に再スローして処理させる