from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import matplotlib.pyplot as plt
import sqlite3
import random
import logging
import traceback
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Constants
MAX_WORKERS = 4  # Reduced to prevent resource exhaustion
REQUEST_TIMEOUT = 15  # Increased timeout
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

# Initialize databases
def init_db():
    try:
        # Main database
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
        
        # Used IPs database
        conn = sqlite3.connect("used_ips.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS used_ips
                     (ip TEXT PRIMARY KEY, 
                      proxy TEXT, 
                      date TEXT)''')
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        logger.error(traceback.format_exc())

init_db()

def get_ip_from_proxy(proxy):
    try:
        logger.debug(f"Getting IP for proxy: {proxy[:20]}...")
        parts = proxy.strip().split(":")
        if len(parts) < 4:
            logger.error(f"Invalid proxy format: {proxy}. Expected host:port:user:pass")
            return None
            
        host, port, user, pw = parts[0], parts[1], parts[2], ":".join(parts[3:])
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        response = session.get(
            "https://api.ipify.org", 
            proxies=proxies, 
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        ip = response.text
        logger.debug(f"Got IP {ip} for proxy: {host}:{port}...")
        return ip
    except Exception as e:
        logger.error(f"Failed to get IP from proxy: {str(e)}")
        return None

def get_fraud_score(ip, proxy_line):
    try:
        logger.debug(f"Checking fraud score for IP: {ip}")
        parts = proxy_line.strip().split(":")
        if len(parts) < 4:
            return None
            
        host, port, user, pw = parts[0], parts[1], parts[2], ":".join(parts[3:])
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
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
                score = int(score_text)
                logger.debug(f"Fraud score for {ip}: {score}")
                return score
        logger.warning(f"Couldn't find fraud score for {ip}")
        return None
    except Exception as e:
        logger.error(f"Error checking Scamalytics for {ip}: {str(e)}")
        return None

def single_check_proxy(proxy_line):
    try:
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        logger.debug(f"Checking proxy: {proxy_line[:20]}...")
        
        ip = get_ip_from_proxy(proxy_line)
        if not ip:
            return None

        score = get_fraud_score(ip, proxy_line)
        if score == 0:
            logger.info(f"✅ Good proxy found: {proxy_line[:20]}...")
            return {"proxy": proxy_line, "ip": ip}
        else:
            logger.debug(f"Proxy {proxy_line[:20]}... has score {score}")
        return None
    except Exception as e:
        logger.error(f"Error in proxy check: {str(e)}")
        return None

def log_good_proxy(proxy):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO good_proxies (proxy) VALUES (?)", (proxy,))
        conn.commit()
    except Exception as e:
        logger.error(f"Error logging good proxy: {str(e)}")
    finally:
        if conn:
            conn.close()

def log_daily_check(good_count):
    try:
        today = datetime.date.today().isoformat()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO check_logs (check_date, good_count)
                     VALUES (?, ?)
                     ON CONFLICT(check_date) DO UPDATE SET
                     good_count = good_count + excluded.good_count''',
                  (today, good_count))
        conn.commit()
        logger.info(f"Logged daily check: {good_count} good proxies")
    except Exception as e:
        logger.error(f"Error logging daily check: {str(e)}")
    finally:
        if conn:
            conn.close()

# Used IPs functions
def add_used_ip(ip, proxy):
    try:
        conn = sqlite3.connect("used_ips.db")
        c = conn.cursor()
        date_str = datetime.datetime.utcnow().isoformat()
        c.execute("INSERT OR REPLACE INTO used_ips (ip, proxy, date) VALUES (?, ?, ?)",
                  (ip, proxy, date_str))
        conn.commit()
        logger.info(f"Added used IP: {ip}")
    except Exception as e:
        logger.error(f"Error adding used IP: {str(e)}")
    finally:
        if conn:
            conn.close()

def is_ip_used(ip):
    try:
        conn = sqlite3.connect("used_ips.db")
        c = conn.cursor()
        c.execute("SELECT 1 FROM used_ips WHERE ip=?", (ip,))
        result = c.fetchone() is not None
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Error checking IP usage: {str(e)}")
        return False

def delete_used_ip(ip):
    try:
        conn = sqlite3.connect("used_ips.db")
        c = conn.cursor()
        c.execute("DELETE FROM used_ips WHERE ip=?", (ip,))
        conn.commit()
        deleted = c.rowcount > 0
        conn.close()
        return deleted
    except Exception as e:
        logger.error(f"Error deleting used IP: {str(e)}")
        return False

def list_used_ips():
    try:
        conn = sqlite3.connect("used_ips.db")
        c = conn.cursor()
        c.execute("SELECT ip, proxy, date FROM used_ips")
        results = []
        for row in c.fetchall():
            results.append({
                "IP": row[0],
                "Proxy": row[1],
                "Date": row[2]
            })
        conn.close()
        return results
    except Exception as e:
        logger.error(f"Error listing used IPs: {str(e)}")
        return []

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    logger.info(f"Handling {request.method} request for /")
    
    try:
        if request.method == "POST":
            logger.info("Processing proxy check request")
            proxies = []
            all_lines = []
            input_count = 0
            truncation_warning = ""
            valid_proxies = []

            if 'proxyfile' in request.files and request.files['proxyfile'].filename:
                logger.info("Processing file upload")
                file = request.files['proxyfile']
                all_lines = file.read().decode("utf-8").strip().splitlines()
                input_count = len(all_lines)
                logger.info(f"Read {input_count} proxies from file")
                
                if input_count > PROXY_CHECK_HARD_LIMIT:
                    truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                    all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
                    logger.warning(f"Truncated to {PROXY_CHECK_HARD_LIMIT} proxies")
                    
                proxies = all_lines
            elif 'proxytext' in request.form:
                proxytext = request.form.get("proxytext", "")
                all_lines = proxytext.strip().splitlines()
                input_count = len(all_lines)
                logger.info(f"Read {input_count} proxies from text input")
                
                if input_count > PROXY_CHECK_HARD_LIMIT:
                    truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                    all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
                    logger.warning(f"Truncated to {PROXY_CHECK_HARD_LIMIT} proxies")
                    
                proxies = all_lines

            # Validate proxy format
            for p in proxies:
                p = p.strip()
                if p and len(p.split(':')) >= 4:
                    valid_proxies.append(p)
                else:
                    logger.warning(f"Invalid proxy format skipped: {p}")
            
            valid_proxies = list(set(valid_proxies))
            processed_count = len(valid_proxies)
            logger.info(f"Processing {processed_count} valid proxies")

            if valid_proxies:
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = [executor.submit(single_check_proxy, proxy) for proxy in valid_proxies]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            logger.info(f"Checking if IP is used: {result['ip']}")
                            used = is_ip_used(result["ip"])
                            results.append({
                                "proxy": result["proxy"],
                                "used": used
                            })
                            log_good_proxy(result["proxy"])

                if results:
                    good_results = [r for r in results if not r['used']]
                    log_daily_check(len(good_results))
                    good_count = len(good_results)
                    used_count = len(results) - good_count
                    
                    message = f"✅ Processed {processed_count} proxies ({input_count} submitted). Found {good_count} good proxies ({used_count} used).{truncation_warning}"
                    logger.info(message)
                else:
                    message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted). No good proxies found.{truncation_warning}"
                    logger.info(message)
            else:
                message = f"⚠️ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats."
                logger.warning(message)
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        logger.error(traceback.format_exc())
        message = "Internal server error. Please try again later."

    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    logger.info("Tracking used proxy")
    try:
        data = request.get_json()
        if data and "proxy" in data:
            logger.info(f"Tracking proxy: {data['proxy'][:20]}...")
            ip = get_ip_from_proxy(data["proxy"])
            if ip:
                add_used_ip(ip, data["proxy"])
                logger.info(f"Tracked IP: {ip}")
            return jsonify({"status": "success"})
        return jsonify({"status": "error"}), 400
    except Exception as e:
        logger.error(f"Error tracking used proxy: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error"}), 500

@app.route("/delete-used-ip/<ip>")
def delete_used_ip(ip):
    logger.info(f"Deleting used IP: {ip}")
    try:
        delete_used_ip(ip)
        return redirect(url_for("admin"))
    except Exception as e:
        logger.error(f"Error deleting used IP: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for("admin"))

@app.route("/admin")
def admin():
    logger.info("Loading admin panel")
    stats = {"total_checks": 0, "total_good": 0}
    logs = []
    daily_data = {}
    
    try:
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
            logger.info("Generated proxy stats graph")
    except Exception as e:
        logger.error(f"Error in admin panel: {str(e)}")
        logger.error(traceback.format_exc())

    used_ips = list_used_ips()
    return render_template("admin.html", logs=logs, stats=stats, 
                           graph_url="/static/proxy_stats.png", 
                           used_ips=used_ips)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    logger.info("Starting application")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)