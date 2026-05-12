$env:BITNET_SERVER_WRAP_KEY_FILE = "D:\BitNet\secrets\server_key.txt"
Set-Location D:\BitNet
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000