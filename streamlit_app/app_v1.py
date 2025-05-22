# app.py (修正案)
import streamlit as st
import jwt
from datetime import datetime, timezone, timedelta
import os

# --- 定数 ---
USER_INFO_KEY = "user_info"
AUTH_ERROR_KEY = "auth_error_message"

# --- 設定値の読み込み ---
# グローバル変数として定義し、try-except内で値を設定
JWT_SECRET_KEY = None
AUTH_LOGIN_URL = None
EXPECTED_ISSUER = None
EXPECTED_AUDIENCE = None

try:
    JWT_SECRET_KEY = st.secrets["JWT_SECRET_KEY"]
    AUTH_LOGIN_URL = st.secrets["AUTH_LOGIN_URL"]
    # secrets.toml に以下のキー名で定義されていることを期待
    # もしキー名が異なる場合は、app.py側かtoml側のどちらかを合わせる
    EXPECTED_ISSUER = st.secrets.get("FUNCTION_BASE_URL", os.environ.get("JWT_EXPECTED_ISSUER"))
    EXPECTED_AUDIENCE = st.secrets.get("STREAMLIT_APP_URL", os.environ.get("JWT_EXPECTED_AUDIENCE"))

except (FileNotFoundError, KeyError) as e:
    st.error(f"secrets.toml の読み込みまたは必須キーの取得に失敗しました: {e}。\n"
             "アプリケーションを正しく設定してください。\n"
             "ローカルテストの場合、プロジェクトルートの .streamlit/secrets.toml ファイルに\n"
             "JWT_SECRET_KEY, AUTH_LOGIN_URL, FUNCTION_BASE_URL, STREAMLIT_APP_URL を設定してください。")
    # 設定ファイルがない、または必須キーがない場合は動作継続が困難なため停止
    st.stop()


# --- ヘルパー関数 ---
def verify_jwt_token(token_string):
    """JWTトークンを検証し、デコードされたペイロードを返す"""
    if not all([JWT_SECRET_KEY, EXPECTED_AUDIENCE, EXPECTED_ISSUER]):
        st.session_state[AUTH_ERROR_KEY] = "アプリケーションの設定が不完全です（キー、発行者、または対象者）。"
        return None
    try:
        payload = jwt.decode(
            token_string,
            JWT_SECRET_KEY,
            algorithms=["HS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            leeway=timedelta(seconds=30)
        )
        return payload
    except:
        pass
        return None

def logout():
    """ログアウト処理"""
    keys_to_delete = [USER_INFO_KEY, AUTH_ERROR_KEY]
    for key in keys_to_delete:
        if key in st.session_state:
            del st.session_state[key]

    # URLからクエリパラメータをクリア (st.query_params が推奨)
    try:
        st.query_params.clear()
    except AttributeError: # 古いStreamlitバージョン (<1.23.0)
        try:
            st.experimental_set_query_params()
        except AttributeError:
            pass # さらに古い場合は何もしない
    st.rerun()

def get_query_param(param_name):
    """クエリパラメータを取得するヘルパー (バージョン互換性のため)"""
    try:
        return st.query_params.get(param_name)
    except AttributeError: # 古いStreamlitバージョン (<1.23.0)
        try:
            params_dict = st.experimental_get_query_params()
            return params_dict.get(param_name, [None])[0]
        except AttributeError:
            return None

# --- メインロジック ---
st.set_page_config(page_title="Streamlit Google Auth Demo", layout="wide")
st.title("🔒 Streamlit Google認証デモ (Firestoreなし版)")

auth_token = get_query_param("auth_token")
auth_error_from_url = get_query_param("auth_error")

# URL経由のエラー処理
if auth_error_from_url and USER_INFO_KEY not in st.session_state:
    error_message = "認証エラーが発生しました。"
    if auth_error_from_url == "unauthorized_user":
        error_message = "アクセスが許可されていません。このアプリケーションの利用権限がありません。"
    else:
        error_message = f"認証エラー: {auth_error_from_url}"
    st.error(error_message)
    # エラーパラメータをURLから消す
    try:
        current_params = st.query_params.to_dict()
        if "auth_error" in current_params: del current_params["auth_error"]
        st.query_params.from_dict(current_params)
    except AttributeError:
        try: st.experimental_set_query_params()
        except AttributeError: pass


# ログイン状態の処理
if USER_INFO_KEY not in st.session_state:
    if auth_token:
        st.write("認証トークンを検証中...")
        user_payload = verify_jwt_token(auth_token)
        if user_payload:
            st.session_state[USER_INFO_KEY] = user_payload
            # 検証成功後、URLからauth_tokenを削除
            try:
                current_params = st.query_params.to_dict()
                if "auth_token" in current_params: del current_params["auth_token"]
                st.query_params.from_dict(current_params)
            except AttributeError:
                try: st.experimental_set_query_params()
                except AttributeError: pass
            st.success("ログインに成功しました！")
            st.rerun()
        # else: 検証失敗。エラーは verify_jwt_token 内で AUTH_ERROR_KEY にセット済。
        #      この後のifブロックでエラー表示とログインボタン表示。
    # else: トークンなし。ログインボタン表示へ。
# else: ログイン済み。保護されたコンテンツ表示へ。


# --- 画面表示 ---
if USER_INFO_KEY in st.session_state:
    user_info = st.session_state[USER_INFO_KEY]
    st.sidebar.subheader("👤 ユーザー情報")
    st.sidebar.write(f"ようこそ、 **{user_info.get('name', 'ユーザー')}** さん！")
    st.sidebar.write(f"メールアドレス: {user_info.get('email')}")
    st.sidebar.write(f"トークン発行者: `{user_info.get('iss')}`") # バッククォートで囲むと見やすい
    st.sidebar.write(f"トークン対象者: `{user_info.get('aud')}`")
    exp_timestamp = user_info.get('exp')
    if exp_timestamp:
        exp_datetime = datetime.fromtimestamp(exp_timestamp, timezone.utc)
        st.sidebar.write(f"トークン有効期限 (UTC): {exp_datetime.strftime('%Y-%m-%d %H:%M:%S')}")

    if st.sidebar.button("🚪 ログアウト", type="primary"):
        logout()

    st.header("ようこそ！保護されたページです")
    st.markdown("このページはGoogle認証を通過したユーザーのみが閲覧できます。")
    st.balloons()
    st.image("https://streamlit.io/images/brand/streamlit-logo-secondary-colormark-darktext.svg", width=300)
else:
    st.info("このアプリケーションを利用するにはGoogleアカウントでのログインが必要です。")

    if AUTH_ERROR_KEY in st.session_state and st.session_state[AUTH_ERROR_KEY]:
        st.error(st.session_state[AUTH_ERROR_KEY])
        del st.session_state[AUTH_ERROR_KEY] # 一度表示したら消す

    if AUTH_LOGIN_URL: # AUTH_LOGIN_URLがNoneでないことを確認
        # st.link_button が推奨 (Streamlit 1.17.0 以降)
        if hasattr(st, 'link_button'):
            st.link_button("Googleアカウントでログイン", AUTH_LOGIN_URL, type="primary", use_container_width=True)
        else: # 古いバージョン向けのHTMLリンク
            login_button_html = f'<a href="{AUTH_LOGIN_URL}" target="_self" style="display: block; width: calc(100% - 2em); margin: 1em auto; padding: 0.75em 1em; background-color: #FF4B4B; color: white; text-align: center; text-decoration: none; border-radius: 0.25rem; font-weight: bold; border: none; cursor: pointer;">Googleアカウントでログイン</a>'
            st.markdown(login_button_html, unsafe_allow_html=True)
    else:
        st.error("ログインURLが設定されていません。管理者に連絡してください。")


    st.markdown("---")
    st.subheader("このデモについて")
    st.markdown("""
    このStreamlitアプリケーションは、Google OAuth 2.0 と JWT を使用してユーザー認証を実装しています。
    認証処理は外部の認証サーバー（ローカルFlaskサーバーまたはCloud Functions）で行われます。
    """)

st.markdown("---")
st.markdown("<div style='text-align: center; color: grey; font-size: 0.9em;'>Powered by Streamlit</div>", unsafe_allow_html=True)