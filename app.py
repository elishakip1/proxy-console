from flask import Flask, request, render_template, redirect, url_for, jsonify, send_from_directory
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import matplotlib.pyplot as plt
import sqlite3
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from sheets_util import get_sheet, add_used_ip, is_ip_used_sheets, delete_used_ip_sheets, list_used_ips_sheets

app = Flask(__name__)

# Constants
MAX_WORKERS = 8
REQUEST_TIMEOUT = 8
PROXY_CHECK_HARD_LIMIT = 50
MIN_DELAY = 0.5
MAX_DELAY = 2.5
DB_PATH = "proxies.db"

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS good_proxies (
                 id INTEGER PRIMARY KEY,
                 proxy TEXT UNIQUE NOT NULL,
                 added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS check_logs (
                 id INTEGER PRIMARY KEY,
                 check_date DATE UNIQUE,
                 good_count INTEGER)''')
    conn.commit()
    conn.close()

init_db()

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        ip = session.get(
            "https://api.ipify.org", 
            proxies=proxies, 
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        ).text
        return ip
    except Exception as e:
        print(f"❌ Failed to get IP from proxy {proxy}: {e}")
        return None

def get_fraud_score(ip, proxy_line):
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        url = f"https://scamalytics.com/ip/{ip}"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        response = session.get(url, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score_text = score_div.text.strip().split(":")[1].strip()
                return int(score_text)
    except Exception as e:
        print(f"⚠️ Error checking Scamalytics for {ip}: {e}")
    return None

def single_check_proxy(proxy_line):
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line)
    if score == 0:
        return {"proxy": proxy_line, "ip": ip}
    return None

def log_good_proxy(proxy):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO good_proxies (proxy) VALUES (?)", (proxy,))
    conn.commit()
    conn.close()

def log_daily_check(good_count):
    today = datetime.date.today().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO check_logs (check_date, good_count)
                 VALUES (?, ?)
                 ON CONFLICT(check_date) DO UPDATE SET
                 good_count = good_count + excluded.good_count''',
              (today, good_count))
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""

    if request.method == "POST":
        proxies = []
        all_lines = []
        input_count = 0
        truncation_warning = ""

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            all_lines = file.read().decode("utf-8").strip().splitlines()
            input_count = len(all_lines)
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines

        proxies = list(set(p.strip() for p in proxies if p.strip()))
        processed_count = len(proxies)

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy) for proxy in proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        used = is_ip_used_sheets(result["ip"])
                        results.append({
                            "proxy": result["proxy"],
                            "used": used
                        })
                        log_good_proxy(result["proxy"])

            if results:
                log_daily_check(len([r for r in results if not r['used']]))
                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])
                
                message = f"✅ Processed {processed_count} proxies ({input_count} submitted). Found {good_count} good proxies ({used_count} used).{truncation_warning}"
            else:
                message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted). No good proxies found.{truncation_warning}"
        else:
            message = f"⚠️ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats."

    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        ip = get_ip_from_proxy(data["proxy"])
        if ip:
            add_used_ip(ip, data["proxy"])
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route("/delete-used-ip/<ip>")
def delete_used_ip(ip):
    delete_used_ip_sheets(ip)
    return redirect(url_for("admin"))

@app.route("/admin")
def admin():
    stats = {}
    logs = []
    daily_data = {}
    
    # Get stats from database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Total checks
    c.execute("SELECT COUNT(*) FROM check_logs")
    stats["total_checks"] = c.fetchone()[0]
    
    # Total good proxies
    c.execute("SELECT SUM(good_count) FROM check_logs")
    stats["total_good"] = c.fetchone()[0] or 0
    
    # Daily logs
    c.execute("SELECT check_date, good_count FROM check_logs ORDER BY check_date DESC")
    for row in c.fetchall():
        logs.append(f"{row[0]},{row[1]} proxies")
        daily_data[row[0]] = row[1]
    
    conn.close()
    
    # Generate graph
    if daily_data:
        dates = list(daily_data.keys())
        counts = list(daily_data.values())
        plt.figure(figsize=(10, 4))
        plt.plot(dates, counts, marker="o", color="green")
        plt.title("Good Proxies per Day")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        if not os.path.exists("static"):
            os.makedirs("static")
        plt.savefig("static/proxy_stats.png")
        plt.close()

    used_ips = list_used_ips_sheets()
    return render_template("admin.html", logs=logs, stats=stats, 
                           graph_url="/static/proxy_stats.png", 
                           used_ips=used_ips)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)