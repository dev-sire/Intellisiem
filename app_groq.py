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

# Groq API Key und Header
GROQ_API_KEY = "gsk_xxx"
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

# Ersetzen Sie 'your_token_here' durch Ihren tatsächlichen Token
HF_TOKEN = "hf_XXX"

# Überprüfen, ob das Modell bereits lokal vorhanden ist
if not os.path.exists(MODEL_PATH):
    print("Lade Modell von Hugging Face herunter...")
    try:
        # Herunterladen der Modell-Datei von Huggingface Hub
        model_file = hf_hub_download(repo_id=MODEL_ID, filename=FILENAME, use_auth_token=HF_TOKEN)
        # Laden des Modells mit TensorFlow/Keras
        model = tf.keras.models.load_model(model_file)
        # Speichern des Modells lokal für zukünftige Verwendungen
        model.save(MODEL_PATH)
        print("Modell erfolgreich heruntergeladen und gespeichert.")
    except Exception as e:
        print(f"Fehler beim Herunterladen des Modells: {e}")
else:
    print("Lade Modell aus lokalem Speicher...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print("Modell erfolgreich aus lokalem Speicher geladen.")

# Ollama Client initialisieren
ollama_client = OllamaClient(base_url="http://localhost:11434")

# Datenbankverbindung
def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialisieren der Datenbanktabellen
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
        # Tabelle für Systemmetriken (falls noch nicht vorhanden)
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
        # Index für Metrics
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);
        """)
        conn.commit()

# Initialisieren der Datenbank beim Start der Anwendung
initialize_database()

# Funktion zur WHOIS-Abfrage nur für IPv4-Adressen, lokale und IPv6-Adressen werden übersprungen
def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Nicht überprüfbar"
        
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unbekannt")
        city = response.get("city", "Unbekannt")
        state = response.get("state", "Unbekannt")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Fehler"

# Verwendung von deque für Netzwerk-Anfragen mit begrenzter Größe (optional, falls weiterhin verwendet)
MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)

# Funktion für System-Informationen und Hardware-Daten
@app.route('/system-info', methods=['GET'])
def system_info():
    try:
        # CPU Informationen
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total

        # GPU Informationen mit GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "N/A"
            gpu_memory_used = "N/A"
            gpu_memory_total = "N/A"

        # Power Informationen (für Laptops)
        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        # JSON-Antwort zusammenstellen
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

        # Debug-Ausgabe in der Konsole
        print("System Info:", system_info_data)

        return jsonify(system_info_data)

    except Exception as e:
        print("Fehler beim Abrufen der Systeminformationen:", e)
        return jsonify({"error": "Fehler beim Abrufen der Systeminformationen"}), 500

# CNN Modell für Netzwerkpaket-Analyse verwenden
def analyze_packet_with_cnn(packet_data):
    prediction = model.predict(np.array([packet_data]))[0]
    return "verdächtig" if prediction[1] > 0.5 else "normal"

# Funktion, die regelmäßig Systemmetriken, Logs und Netzwerkpakete an den Frontend-Client und Groq übermittelt
def send_system_metrics():
    while True:
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent

        # Sende die Metriken an den Client über WebSocket
        socketio.emit('update_metrics', {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'cpu_frequency': psutil.cpu_freq().current,
            'cpu_cores': psutil.cpu_count(),
            'gpu_usage': 'N/A',  # Beispiel, falls GPU-Infos benötigt werden
            'gpu_memory_used': 'N/A',
            'gpu_memory_total': 'N/A',
            'power_usage': 'N/A',
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total
        })

        # Netzwerkpakete und Logs sammeln
        logs = fetch_recent_logs()
        network_data = fetch_recent_network_data()

        # Groq API Anfrage
        payload = {
            "model": "llama3-8b-8192",  # Das Modell kann hier angepasst werden
            "messages": [
                {"role": "system", "content": f"Systemmetriken: CPU: {cpu_usage}%, RAM: {memory_usage}%, Festplatte: {disk_usage}%."},
                {"role": "user", "content": f"Logs: {logs}, Netzwerk: {network_data}"}
            ]
        }

        try:
            # Groq API Anfrage
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
            response_data = response.json()
            assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "Keine Antwort")
            save_log(f"KI-Antwort: {assistant_message}")
        except requests.RequestException as e:
            print(f"Fehler bei der Anfrage an Groq: {e}")

        time.sleep(5)  # Alle 5 Sekunden

# Funktion, um kürzliche Logs zu erhalten
def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]

# Funktion, um kürzliche Netzwerkdaten zu erhalten
def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute("SELECT ip, country, summary FROM network_requests ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [{"ip": request["ip"], "country": request["country"], "summary": request["summary"]} for request in network_data]


# WebSocket-Handler, der bei jeder Verbindung gestartet wird
@socketio.on('connect')
def handle_connect():
    print("Client verbunden")
    socketio.start_background_task(send_system_metrics)  # Starten des Hintergrundtasks für Metriken

# WebSocket-Handler für das Senden von Logs
@socketio.on('new_log')
def handle_new_log(log_data):
    socketio.emit('new_log', log_data)  # Sende das neue Log an den Client

# WebSocket-Handler für Netzwerkpakete
@socketio.on('new_network_request')
def handle_new_network_request(network_data):
    socketio.emit('new_network_request', network_data)  # Sende die Netzwerk-Anfrage an den Client


# Netzwerkpaket-Callback mit CNN-Modell für Sicherheitsanalyse
# Funktion zur Aktualisierung von `packet_callback`, um die Blacklist-Überprüfung mit Cache zu verwenden
def packet_callback(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        summary = packet.summary()

        # Prüfen, ob die IP lokal, IPv6 oder ausgeschlossen ist
        excluded_ips = {"144.76.114.3", "159.89.102.253"}
        if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
            country = "Lokal/IPv6 oder ausgeschlossen"
            is_blacklisted = False
            attacks = 0
            reports = 0
        else:
            country = get_ip_country(ip)
            blacklist_status = check_ip_blacklist_cached(ip)
            is_blacklisted = blacklist_status["blacklisted"]
            attacks = blacklist_status.get("attacks", 0)
            reports = blacklist_status.get("reports", 0)
        
        # Datenbankeintrag für Netzwerkpakete
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, "IPv4", country, summary, "Ja" if is_blacklisted else "Nein", attacks, reports))
            conn.commit()

        # Loggen und ggf. Benachrichtigung
        log_message = f"Netzwerkpaket von {ip} ({country}) - Blacklisted: {is_blacklisted}"
        save_log(log_message)
        if is_blacklisted:
            notify_ai(log_message)


# Pagination und ältere Logs durchsuchen
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

# Logs nach bestimmten Kriterien durchsuchen
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

# Metriken und Logs speichern
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

# KI-Benachrichtigung bei verdächtigen Aktivitäten (kurze Antworten direkt im Prompt)
def notify_ai(message):
    short_prompt = f"{message}\nAntworte bitte kurz und prägnant, maximal 1-2 Sätze."
    response = ollama_client.generate(prompt=short_prompt)
    save_log(f"KI-Benachrichtigung: {response}")

# Systemmetriken regelmäßig analysieren
def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk > 90:
        message = f"Warnung: Hohe Systemlast - CPU: {cpu}%, RAM: {memory}%, Festplatte: {disk}%."
        notify_ai(message)

# Startseite
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

# Caching-Blacklist-Prüfung
def check_ip_blacklist_cached(ip):
    with get_db_connection() as conn:
        result = conn.execute("SELECT blacklisted, attacks, reports FROM network_requests WHERE ip = ?", (ip,)).fetchone()
        if result:
            # IP bereits geprüft
            return {
                "blacklisted": result["blacklisted"] == "Ja",
                "attacks": result["attacks"],
                "reports": result["reports"]
            }
        
        # API-Anfrage, wenn die IP nicht in der Datenbank ist
        url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
        try:
            response = requests.get(url)
            data = response.json() if response.status_code == 200 else {"blacklisted": False}
            blacklisted = data.get("attacks", 0) > 0
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            
            # Speichern in der Datenbank
            conn.execute(
                "INSERT INTO network_requests (ip, blacklisted, attacks, reports) VALUES (?, ?, ?, ?)",
                (ip, "Ja" if blacklisted else "Nein", attacks, reports)
            )
            conn.commit()

            return {"blacklisted": blacklisted, "attacks": attacks, "reports": reports}
        except requests.RequestException:
            return {"blacklisted": False}

# IP aus Nachricht extrahieren
def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None

# Funktion zur Initialisierung des Groq-Clients
def initialize_groq_client():
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    return headers

# Funktion zur Integration der Groq-Chat-Funktion
@app.route('/chat', methods=['POST'])
def chat_with_groq():
    data = request.get_json()
    user_message = data.get('message', '')

    # Systemmetriken abrufen
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    # Logs und Netzwerkpakete sammeln
    logs = fetch_recent_logs()
    network_data = fetch_recent_network_data()

    context_message = (
        f"{user_message}\n"
        f"Systemmetriken: CPU: {cpu}%, Speicher: {memory}%, Festplatte: {disk}%.\n"
        f"Logs: {logs}, Netzwerk: {network_data}\n"
        "Antworte bitte kurz und prägnant."
    )

    payload = {
        "model": "llama3-8b-8192",  # Das Modell kann hier angepasst werden
        "messages": [{"role": "user", "content": context_message}]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
        response_data = response.json()
        assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "Keine Antwort")
    except requests.RequestException as e:
        print("Fehler bei der Anfrage an Groq:", e)
        assistant_message = f"Fehler bei der Anfrage an Groq: {e}"

    save_log(f"Benutzer: {user_message}, KI: {assistant_message}")
    return jsonify({"response": assistant_message})




# Netzwerk-Anfragen abrufen mit Paginierung
@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        with get_db_connection() as conn:
            requests = conn.execute("""
                SELECT ip, type, country, summary, blacklisted, attacks, reports, timestamp 
                FROM network_requests 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (page_size, offset)).fetchall()
        data = [dict(request) for request in requests]
        return jsonify(data)
    except Exception as e:
        print(f"Fehler beim Abrufen der Netzwerk-Anfragen: {e}")
        return jsonify({"error": "Fehler beim Abrufen der Netzwerk-Anfragen"}), 500


# Starten Sie das Paket-Sniffing in einem separaten Thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True, port=5000, use_reloader=False)
    
