import os
import sys
import webbrowser
import threading
import time
import secrets


def generate_server_key(key_path: str) -> bytes:
    key = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key)
    return key


def main():
    exec_dir = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))

    data_dir = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "BitNet")
    os.makedirs(data_dir, exist_ok=True)

    db_path = os.path.join(data_dir, "bitnet.db")
    db_url = f"sqlite:///{db_path}"

    key_path = os.path.join(data_dir, "server_key.txt")
    if not os.path.exists(key_path):
        generate_server_key(key_path)

    os.environ.setdefault("SQLALCHEMY_DATABASE_URL", db_url)
    os.environ.setdefault("BITNET_SERVER_WRAP_KEY_FILE", key_path)
    os.environ.setdefault("UVICORN_HOST", "127.0.0.1")
    os.environ.setdefault("UVICORN_PORT", "8200")

    from backend.main import app
    import uvicorn

    port = int(os.environ.get("UVICORN_PORT", "8200"))

    def open_browser():
        time.sleep(2)
        webbrowser.open(f"http://127.0.0.1:{port}")

    t = threading.Thread(target=open_browser, daemon=True)
    t.start()

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()