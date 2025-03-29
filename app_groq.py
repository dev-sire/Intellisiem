from flask import Flask, jsonify, request, render_template
import tensorflow as tf
import numpy as np
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import re
import os
from collections import deque
from transformers import TFAutoModel, AutoConfig
import GPUtil
from huggingface_hub import hf_hub_download
from flask_socketio import SocketIO, emit
import time
import eventlet
from config import GROQ_API_KEY, HF_TOKEN

# Groq API Key und Header
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)
socketio = SocketIO(app)


# Modell von Hugging Face laden oder herunterladen, wenn nicht vorhanden
MODEL_PATH = 'SecIDS-CNN.h5'
MODEL_ID = "Keyven/SecIDS-CNN"
FILENAME = "SecIDS-CNN.h5"


if not os.path.exists(MODEL_PATH):
    print("Downloading model from Hugging Face...")
    try:
        # Download the model file from Hugging Face Hub
        model_file = hf_hub_download(repo_id=MODEL_ID, filename=FILENAME, use_auth_token=HF_TOKEN)
        # Load the model with TensorFlow/Keras
        model = tf.keras.models.load_model(model_file)
        # Save the model locally for future use
        model.save(MODEL_PATH)
        print("Model downloaded and saved successfully.")
    except Exception as e:
        print(f"Error downloading the model: {e}")
else:
    print("Loading model from local storage...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print("Model loaded successfully from local storage.")

# Ollama Client initialisieren
ollama_client = OllamaClient(base_url="http://localhost:11434")

def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    with get_db_connection() as conn:
        # Tabelle für Netzwerk-Anfragen
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                type TEXT,
                country TEXT,
                summary TEXT,
                blacklisted TEXT,
                attacks INTEGER,
                reports INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp);
        """)
        # Tabelle für Logs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        # Index für Logs
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL,
                memory REAL,
                disk REAL,
                network INTEGER
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);
        """)
        conn.commit()

initialize_database()

# Function to perform WHOIS query only for IPv4 addresses, skipping local and IPv6 addresses
def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Not verifiable"

        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unknown")
        city = response.get("city", "Unknown")
        state = response.get("state", "Unknown")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Error"

# Using deque for network requests with limited size (optional, if still used)
MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)

# Function for system information and hardware data
@app.route('/system-info', methods=['GET'])
def system_info():
    try:
        # CPU information
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total

        # GPU information with GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "N/A"
            gpu_memory_used = "N/A"
            gpu_memory_total = "N/A"

        # Power information (for laptops)
        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        # Assemble JSON response
        system_info_data = {
            "cpu_frequency": cpu_freq,
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage,
            "gpu_usage": gpu_usage,
            "gpu_memory_used": gpu_memory_used,
            "gpu_memory_total": gpu_memory_total,
            "power_usage": power_usage,
            "memory_total": memory,
            "disk_total": disk
        }

        # Debug output in the console
        print("System Info:", system_info_data)

        return jsonify(system_info_data)

    except Exception as e:
        print("Error retrieving system information:", e)
        return jsonify({"error": "Error retrieving system information"}), 500

# Use CNN model for network packet analysis
def analyze_packet_with_cnn(packet_data):
    prediction = model.predict(np.array([packet_data]))[0]
    return "suspicious" if prediction[1] > 0.5 else "normal"

# Function that regularly transmits system metrics, logs, and network packets to the frontend client and Groq
def send_system_metrics():
    while True:
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent

        # Send the metrics to the client via WebSocket
        socketio.emit('update_metrics', {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'cpu_frequency': psutil.cpu_freq().current,
            'cpu_cores': psutil.cpu_count(),
            'gpu_usage': 'N/A',  # Example, if GPU info is needed
            'gpu_memory_used': 'N/A',
            'gpu_memory_total': 'N/A',
            'power_usage': 'N/A',
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total
        })

        # Collect network packets and logs
        logs = fetch_recent_logs()
        network_data = fetch_recent_network_data()

        # Groq API request
        payload = {
            "model": "llama3-8b-8192",  # The model can be adjusted here
            "messages": [
                {"role": "system", "content": f"System Metrics: CPU: {cpu_usage}%, RAM: {memory_usage}%, Disk: {disk_usage}%."},
                {"role": "user", "content": f"Logs: {logs}, Network: {network_data}"}
            ]
        }

        try:
            # Groq API request
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
            response_data = response.json()
            assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
            save_log(f"AI Response: {assistant_message}")
        except requests.RequestException as e:
            print(f"Error in request to Groq: {e}")

        time.sleep(5)

def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]

def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute("SELECT ip, country, summary FROM network_requests ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [{"ip": request["ip"], "country": request["country"], "summary": request["summary"]} for request in network_data]

@socketio.on('connect')
def handle_connect():
    print("Client verbunden")
    socketio.start_background_task(send_system_metrics)

@socketio.on('new_log')
def handle_new_log(log_data):
    socketio.emit('new_log', log_data)

@socketio.on('new_network_request')
def handle_new_network_request(network_data):
    socketio.emit('new_network_request', network_data)
def packet_callback(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        summary = packet.summary()

        excluded_ips = {"144.76.114.3", "159.89.102.253"}
        if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
            country = "Local/IPv6 or excluded"
            is_blacklisted = False
            attacks = 0
            reports = 0
        else:
            country = get_ip_country(ip)
            blacklist_status = check_ip_blacklist_cached(ip)
            is_blacklisted = blacklist_status["blacklisted"]
            attacks = blacklist_status.get("attacks", 0)
            reports = blacklist_status.get("reports", 0)

        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, "IPv4", country, summary, "Yes" if is_blacklisted else "No", attacks, reports))
            conn.commit()

        log_message = f"Network packet from {ip} ({country}) - Blacklisted: {is_blacklisted}"
        save_log(log_message)
        if is_blacklisted:
            notify_ai(log_message)

@app.route('/logs', methods=['GET'])
def get_logs():
    page = int(request.args.get('page', 1))
    page_size = 50
    offset = (page - 1) * page_size
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (page_size, offset)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

@app.route('/search-logs', methods=['POST'])
def search_logs():
    search_term = request.json.get('query', '')
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            WHERE log LIKE ? 
            ORDER BY timestamp DESC
        """, ('%' + search_term + '%',)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

def save_metrics(cpu, memory, disk, network):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO metrics (timestamp, cpu, memory, disk, network) 
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cpu, memory, disk, network))
        conn.commit()

def save_log(log):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO logs (timestamp, log) 
            VALUES (?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))
        conn.commit()

# AI notification for suspicious activities (short answers directly in the prompt)
def notify_ai(message):
    print("Notify ran..................")
    short_prompt = f"{message}\nPlease respond briefly and concisely, maximum 1-2 sentences."
    response = ollama_client.generate(prompt=short_prompt)
    save_log(f"AI Notification: {response}")

# Regularly analyze system metrics
def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk < 90:
        print("statement ran............................")
        message = f"Warning: High system load - CPU: {cpu}%, RAM: {memory}%, Disk: {disk}%."
        notify_ai(message)

@app.route('/')
def home():
    return render_template('index.html')

# Server-Status
@app.route('/server-status', methods=['GET'])
def server_status():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    print(f"CPU: {cpu}, Memory: {memory}, Disk: {disk}")
    
    save_metrics(cpu, memory, disk, 0)
    analyze_metrics(cpu, memory, disk)
    
    return jsonify({
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk
    })

def check_ip_blacklist_cached(ip):
    with get_db_connection() as conn:
        result = conn.execute("SELECT blacklisted, attacks, reports FROM network_requests WHERE ip = ?", (ip,)).fetchone()
        if result:
            return {
                "blacklisted": result["blacklisted"] == "Ja",
                "attacks": result["attacks"],
                "reports": result["reports"]
            }
        
        url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
        try:
            response = requests.get(url)
            data = response.json() if response.status_code == 200 else {"blacklisted": False}
            blacklisted = data.get("attacks", 0) > 0
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            
            conn.execute(
                "INSERT INTO network_requests (ip, blacklisted, attacks, reports) VALUES (?, ?, ?, ?)",
                (ip, "Ja" if blacklisted else "Nein", attacks, reports)
            )
            conn.commit()

            return {"blacklisted": blacklisted, "attacks": attacks, "reports": reports}
        except requests.RequestException:
            return {"blacklisted": False}

def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None

def initialize_groq_client():
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    return headers

# Function to integrate the Groq chat functionality
@app.route('/chat', methods=['POST'])
def chat_with_groq():
    data = request.get_json()
    user_message = data.get('message', '')

    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    logs = fetch_recent_logs()
    network_data = fetch_recent_network_data()

    context_message = (
        f"{user_message}\n"
        f"System Metrics: CPU: {cpu}%, Memory: {memory}%, Disk: {disk}%.\n"
        f"Logs: {logs}, Network: {network_data}\n"
        "Please respond briefly and concisely."
    )

    payload = {
        "model": "llama3-8b-8192",
        "messages": [{"role": "user", "content": context_message}]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
        response_data = response.json()
        assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
    except requests.RequestException as e:
        print("Error in request to Groq:", e)
        assistant_message = f"Error in request to Groq: {e}"

    save_log(f"User: {user_message}, AI: {assistant_message}")
    return jsonify({"response": assistant_message})

@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        with get_db_connection() as conn:
            requests_data = conn.execute("""
                SELECT ip, type, country, summary, blacklisted, attacks, reports, timestamp 
                FROM network_requests 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (page_size, offset)).fetchall()
        data = [dict(request) for request in requests_data]
        return jsonify(data)
    except Exception as e:
        print(f"Error retrieving network requests: {e}")
        return jsonify({"error": "Error retrieving network requests"}), 500


# Starten Sie das Paket-Sniffing in einem separaten Thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True, port=5000, use_reloader=False)
