from flask import Blueprint, redirect, request, make_response
# 必要な他のモジュールもインポート
import config
import auth_utils # もしルート内で直接使うなら
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
# import jwt # auth_utils が担当

# Blueprintオブジェクトを作成
auth_bp = Blueprint('auth', __name__, url_prefix='/auth') # url_prefix で /auth を共通化も可能

# 定数 (ここか、configから持ってくる)
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
STATE_COOKIE_NAME = "myappstate" # main.pyと共有

# 元の main.py にあったルート関数をここに移動
# @app.route('/') はBlueprintのurl_prefixを考慮して調整するか、別のBlueprintにするか、main.pyに残す
# ここでは /auth_login と /auth_callback を auth_bp に移す例

@auth_bp.route('/login') # url_prefix='/auth' なら、実際のパスは /auth/login
def auth_login_route():
    print("\n--- /auth/login accessed ---") # パスが変わる可能性に注意
    if not all([config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET, config.REDIRECT_URI, SCOPES]):
        # ... (エラー処理)
        pass # 以下、元のロジックを移植

    # ... (元の /auth_login のロジック)
    # oauth_state_param = auth_utils.generate_oauth_state_parameter()
    # ...
    # response.set_cookie(STATE_COOKIE_NAME, oauth_state_param, ...)
    return response # response を返す

@auth_bp.route('/callback') # 実際のパスは /auth/callback
def auth_callback_route():
    print("\n--- /auth/callback accessed ---")
    # ... (元の /auth_callback のロジック)
    # jwt_token = auth_utils.create_custom_jwt(...)
    # ...
    return response_final # response_final を返す

# もしルートパス '/' もこのBlueprintで扱うなら
# root_bp = Blueprint('root', __name__)
# @root_bp.route('/')
# def root_path_handler(): ...