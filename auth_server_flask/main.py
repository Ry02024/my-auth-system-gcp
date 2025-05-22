import os # Cloud Functionsエントリーポイントで os.environ.get を使うため
import argparse # ローカル実行時の引数パースに必要
from flask import Flask
import config # 相対インポートに変更
from auth_routes import auth_bp # 作成したBlueprintをインポート

import functions_framework

app = Flask(__name__)

# --- Blueprintの登録 ---
app.register_blueprint(auth_bp)

# --- Cloud Functionsエントリーポイント ---
@functions_framework.http
def auth_http(request_cf):
    # Cloud Functions インスタンス起動時/リクエスト処理前に必ず設定を初期化
    # config.are_configs_initialized() は config.py で定義されている想定
    # または、より単純に毎回初期化を試みる (config.py側で重複実行を抑制する)
    # 今回は initialize_app_configs が冪等性を持つ（何度呼んでも同じ結果になる）ことを期待
    try:
        print("DEBUG (auth_http entry): Attempting to initialize/ensure configs are initialized.")
        # Cloud Functions環境では、ENV環境変数が設定されていることを期待
        # GCP_PROJECTも環境変数から取得する
        current_env_mode = os.environ.get("ENV", "prod") # デフォルトは prod
        
        # config.GCP_PROJECT_ID の設定を config.initialize_app_configs に任せるか、
        # ここで明示的に設定するかは config.py の実装による。
        # config.py が os.environ.get('GCP_PROJECT') を読むならここでは不要。
        # GCP_PROJECT_ID_from_env = os.environ.get("GCP_PROJECT")
        # if not GCP_PROJECT_ID_from_env:
        #     print("CRITICAL (auth_http): GCP_PROJECT environment variable is not set in Cloud Function.")
            # return "Server configuration error: GCP_PROJECT not set.", 500
        # config.GCP_PROJECT_ID = GCP_PROJECT_ID_from_env # config.py に渡す場合

        config.initialize_app_configs(mode_from_arg=current_env_mode)

        # 必須設定値の再チェック (config.initialize_app_configs内でも行われるが念のため)
        if not all([config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET, config.JWT_SECRET_KEY,
                    config.STREAMLIT_APP_URL, config.FUNCTION_BASE_URL, config.REDIRECT_URI]):
            print("CRITICAL (auth_http): Essential configurations are missing after init attempt.")
            return "Server configuration error: Essential configurations missing.", 500

    except Exception as e:
        print(f"CRITICAL (auth_http entry): Failed to initialize configs: {e}")
        # 適切なエラーレスポンスを返す
        return "Server configuration error during request processing.", 500

    # Flaskアプリのコンテキストでリクエストを処理
    with app.request_context(request_cf.environ):
        return app.full_dispatch_request()

# --- スクリプトとして直接実行された場合の処理 (ローカル開発用) ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Flask OAuth Authentication Server (Local)")
    parser.add_argument(
        "--mode",
        type=str,
        choices=['local_direct', 'local_sm_test', 'prod'],
        default=os.environ.get("ENV_ARG", os.environ.get("ENV", "local_direct")).lower(),
        help="動作モードを選択します。 (例: local_direct, local_sm_test)"
    )
    args = parser.parse_args()

    try:
        print(f"DEBUG __main__: Initializing configs with mode: {args.mode}")
        config.initialize_app_configs(args.mode) # ★ コメントアウトを解除し、引数を渡す
    except ValueError as e:
        print(f"設定エラーが発生しました: {e}")
        exit(1)
    except RuntimeError as e:
        print(f"ランタイムエラーが発生しました: {e}")
        exit(1)
    except Exception as e:
        print(f"予期せぬ初期化エラーが発生しました: {e}")
        exit(1)

    # 起動前チェック (configモジュールの値を使って)
    if not all([config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET, config.JWT_SECRET_KEY,
                config.STREAMLIT_APP_URL, config.FUNCTION_BASE_URL, config.REDIRECT_URI]):
        print("エラー: Flaskアプリの起動に必要な設定が完了していません。")
        print("       config.py の initialize_app_configs のログと、環境変数/ .env ファイルを確認してください。")
        print(f"       Current ENV_TYPE: {config.ENV_TYPE}")
        # 必要に応じて他の設定値も表示
        exit(1)
    else:
        print(f"\n--- ローカルサーバー起動準備完了 (Flask, Mode: {config.ENV_TYPE}) ---")
        print(f"使用するGCPプロジェクト (参考): '{config.GCP_PROJECT_ID}'")
        print(f"関数ベースURL (FUNCTION_BASE_URL): {config.FUNCTION_BASE_URL}")
        print(f"リダイレクトURI (REDIRECT_URI): {config.REDIRECT_URI}")
        print(f"StreamlitアプリURL (STREAMLIT_APP_URL): {config.STREAMLIT_APP_URL}")
        print(f"Listen on http://0.0.0.0:8080")
        # ★★★ app.run() の引数を具体的に指定 ★★★
        app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)