#!/bin/bash
echo "🚀 Starting Cyber Risk Assessment System (WSL Linux Mode)..."

# --- BACKEND ---
echo "➡ Starting backend..."
cd ~/cyber-risk/backend
source venv/bin/activate
export FLASK_PORT=5050
export NIKTO_MODE=WSL
export NIKTO_TIMEOUT=180
python3 app.py &
BACKEND_PID=$!

sleep 2

# --- FRONTEND ---
echo "➡ Starting Streamlit UI..."
cd ~/cyber-risk/ui
source venv/bin/activate
export BACKEND_URL="http://127.0.0.1:5050"
streamlit run frontend_app.py &

echo "✅ System running!"
wait
