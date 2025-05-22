import os
import argparse
# import uuid # auth_utils に移動したので不要になる
from datetime import datetime, timedelta, timezone # auth_utils でも使うが、main.py で直接は使わなくなる可能性

import functions_framework
from flask import Flask, redirect, request, make_response
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
# import jwt # auth_utils に移動したので不要になる

# 設定モジュールとユーティリティモジュールをインポート
import config # `.` を付けて同じディレクトリ内であることを明示
import auth_utils # `.` を付けて同じディレクトリ内であることを明示

# Flaskアプリケーションインスタンス
app = Flask(__name__)

# --- Flaskルート定義 ---
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
STATE_COOKIE_NAME = "myappstate"

@app.route('/')
def root_path_handler():
    print("--- / (root) accessed ---")
    return "Authentication Service. Please go to /auth_login to start.", 200

@app.route('/auth_login', methods=['GET'])
def auth_login_route():
    print("\n--- /auth_login accessed ---")
    if not all([config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET, config.REDIRECT_URI, SCOPES]):
        print("エラー: OAuth設定不完全(login)。 configの値を確認してください。")
        return "サーバー設定エラー (login)", 500

    client_config_dict = {"web": {"client_id": config.GOOGLE_CLIENT_ID,
                                  "client_secret": config.GOOGLE_CLIENT_SECRET,
                                  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                                  "token_uri": "https://oauth2.googleapis.com/token",
                                  "project_id": config.GCP_PROJECT_ID,
                                  "redirect_uris": [config.REDIRECT_URI]}}
    try:
        flow = Flow.from_client_config(client_config=client_config_dict, scopes=SCOPES, redirect_uri=config.REDIRECT_URI)
    except Exception as e:
        print(f"Flow初期化失敗: {e}")
        return "OAuthフロー設定エラー", 500

    # oauth_state_param = str(uuid.uuid4()) # 元のコード
    oauth_state_param = auth_utils.generate_oauth_state_parameter() # ★ 修正 ★
    authorization_url, _ = flow.authorization_url(access_type='offline', state=oauth_state_param, prompt='consent')

    print(f"DEBUG auth_login: REDIRECT_URI to be used = {config.REDIRECT_URI}")
    print(f"DEBUG auth_login: Auth URL (first 100 chars) = {authorization_url[:100]}")

    response = make_response(redirect(authorization_url))
    is_secure = (config.ENV_TYPE == 'prod')
    response.set_cookie(STATE_COOKIE_NAME, oauth_state_param, max_age=600, httponly=True, secure=is_secure, samesite='Lax')
    print(f"Login: State '{oauth_state_param}' set to Cookie '{STATE_COOKIE_NAME}' (secure={is_secure}, samesite='Lax'). Redirecting to Google.")
    return response

@app.route('/auth_callback', methods=['GET'])
def auth_callback_route():
    # ... (前半の State 検証、Googleからのトークン取得、IDトークン検証、ユーザー許可リストチェックまでは変更なし) ...
    print("\n--- /auth_callback accessed ---")
    print(f"Callback: Query Args: {request.args.to_dict()}")
    returned_state = request.args.get('state')
    code = request.args.get('code')
    error = request.args.get('error')
    is_secure = (config.ENV_TYPE == 'prod')

    if error:
        print(f"Callback Error from Google: {error}")
        return f"Google認証エラー: {error}", 400
    if not code:
        print("Callback Error: No code provided by Google.")
        return "Googleから認証コードが提供されませんでした。", 400

    original_state = request.cookies.get(STATE_COOKIE_NAME)
    if not original_state:
        print("Callback Error: State Cookie not found. Session might be invalid.")
        return "セッション情報が無効です (State Cookie が見つかりません)。", 400
    if returned_state != original_state:
        print("Callback Error: State mismatch. Possible CSRF attack.")
        resp_csrf = make_response("不正なリクエストです (CSRFの可能性)。", 400)
        resp_csrf.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
        return resp_csrf
    print("Callback: State validation successful.")

    client_config_dict_cb = {"web": {"client_id": config.GOOGLE_CLIENT_ID,
                                     "client_secret": config.GOOGLE_CLIENT_SECRET,
                                     "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                                     "token_uri": "https://oauth2.googleapis.com/token",
                                     "project_id": config.GCP_PROJECT_ID,
                                     "redirect_uris": [config.REDIRECT_URI]}}
    try:
        flow = Flow.from_client_config(client_config=client_config_dict_cb, scopes=SCOPES, state=returned_state)
        flow.redirect_uri = config.REDIRECT_URI
        flow.fetch_token(code=code)
        credentials = flow.credentials
        if not credentials or not credentials.id_token:
            print("Callback Error: Failed to obtain ID token from credentials.")
            raise Exception("IDトークンが取得できませんでした。")
        print(f"Callback: Token fetch successful. ID Token (first 30 chars): {credentials.id_token[:30]}...")
    except Exception as e:
        print(f"Callback Error: Token fetch failed: {e}")
        resp_token_err = make_response(f"トークンの取得に失敗しました: {e}", 500)
        resp_token_err.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
        return resp_token_err

    try:
        id_info = id_token.verify_oauth2_token(credentials.id_token, GoogleAuthRequest(), config.GOOGLE_CLIENT_ID)
        user_email = id_info.get("email")
        user_name = id_info.get("name", user_email)
        print(f"Callback: ID token verification successful. Email:'{user_email}', Name:'{user_name}'")

        if user_email not in config.ALLOWED_USERS_LIST:
            print(f"Callback Warn: User '{user_email}' is not in ALLOWED_USERS_LIST.")
            err_redir_url = f"{config.STREAMLIT_APP_URL}?auth_error=unauthorized_user&email={user_email}"
            resp_unauth = make_response(redirect(err_redir_url))
            resp_unauth.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
            return resp_unauth
        print(f"Callback Info: User '{user_email}' is allowed. Generating custom JWT.")
    except Exception as e:
        print(f"Callback Error: ID token verification or access control failed: {e}")
        resp_id_err = make_response(f"ユーザー情報の検証に失敗しました: {e}", 500)
        resp_id_err.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
        return resp_id_err

    # JWTペイロードの作成とエンコードの部分を auth_utils を使って書き換え
    # # JWTペイロードの作成 # 元のコード
    # jwt_payload = {
    #     "sub": user_email,
    #     "name": user_name,
    #     "email": user_email,
    #     "iss": config.FUNCTION_BASE_URL, # 発行者
    #     "aud": config.STREAMLIT_APP_URL, # 対象者
    #     "exp": datetime.now(timezone.utc) + timedelta(hours=1), # 有効期限
    #     "iat": datetime.now(timezone.utc) # 発行日時
    # }
    try:
        # jwt_token = jwt.encode(jwt_payload, config.JWT_SECRET_KEY, algorithm="HS256") # 元のコード
        jwt_token = auth_utils.create_custom_jwt( # ★ 修正 ★
            user_email=user_email,
            user_name=user_name,
            issuer_url=config.FUNCTION_BASE_URL,
            audience_url=config.STREAMLIT_APP_URL,
            jwt_secret_key=config.JWT_SECRET_KEY
            # expires_delta_hours は auth_utils.create_custom_jwt のデフォルト値 (1時間) を使用
        )
        # print(f"Callback: Custom JWT generation successful. Token (first 20 chars): {jwt_token[:20]}...") # auth_utils内で行う
    except Exception as e:
        print(f"Callback Error: Custom JWT generation failed: {e}") # auth_utils から再スローされたエラーをキャッチ
        resp_jwt_err = make_response(f"セッショントークンの生成に失敗しました: {e}", 500)
        resp_jwt_err.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
        return resp_jwt_err

    # Streamlitアプリへリダイレクト
    target_url = f"{config.STREAMLIT_APP_URL}?auth_token={jwt_token}"
    response_final = make_response(redirect(target_url))
    response_final.delete_cookie(STATE_COOKIE_NAME, path='/', secure=is_secure, httponly=True, samesite='Lax')
    print(f"Callback: Redirecting to Streamlit App (URL up to 30 chars after base: {target_url[:len(config.STREAMLIT_APP_URL)+30]}...).")
    return response_final

# --- Cloud Functionsエントリーポイント ---
# (変更なし)
@functions_framework.http
def auth_http(request_cf):
    if not config.are_configs_initialized():
        print("DEBUG (auth_http entry): Configs not initialized or GCP_PROJECT_ID missing. Attempting explicit init from ENV.")
        try:
            config.initialize_app_configs(mode_from_arg=os.environ.get("ENV"))
            if not config.GCP_PROJECT_ID:
                 config.GCP_PROJECT_ID = os.environ.get("GCP_PROJECT")
                 if not config.GCP_PROJECT_ID:
                     print("CRITICAL (auth_http): GCP_PROJECT is still not set after re-init attempt.")
        except Exception as e:
            print(f"CRITICAL (auth_http entry): Failed to initialize configs: {e}")
            return "Server configuration error during request processing.", 500
    with app.request_context(request_cf.environ):
        return app.full_dispatch_request()

# --- スクリプトとして直接実行された場合の処理 (ローカル開発用) ---
# (変更なし)
if __name__ == '__main__':
    # ... (省略) ...
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)