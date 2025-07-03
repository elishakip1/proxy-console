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
import json

# --- Google Sheets Imports ---
import gspread
from oauth2client.service_account import ServiceAccountCredentials


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
MAX_WORKERS = 4
REQUEST_TIMEOUT = 15
PROXY_CHECK_HARD_LIMIT = 50
MIN_DELAY = 0.5
MAX_DELAY = 2.5
DB_PATH = "proxies.db"

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
]

# --- Google Sheets Configuration ---
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

def get_gsheet_client():
    """Initializes and returns the Google Sheets client using environment credentials."""
    try:
        json_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
        if not json_creds:
            logger.error("Missing GOOGLE_SERVICE_ACCOUNT_JSON environment variable.")
            raise ValueError("Google credentials not found in environment variables.")
        
        creds_dict = json.loads(json_creds)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
        client = gspread.authorize(creds)
        return client
    except Exception as e:
        logger.error(f"Failed to get Google Sheet client: {e}")
        logger.error(traceback.format_exc())
        return None

def get_sheet():
    """Opens and returns the 'UsedIPs' worksheet."""
    try:
        client = get_gsheet_client()
        if client:
            return client.open("UsedIPs").sheet1
    except Exception as e:
        logger.error(f"Failed to get Google Sheet: {e}")
        return None

# Initialize local DB for stats
def init_db():
    try:
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
        if len(parts) < 4: return None
            
        host, port, user, pw = parts[0], parts[1], parts[2], ":".join(parts[3:])
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        url = f"https://scamalytics.com/ip/{ip}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        response = session.get(url, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score = int(score_div.text.strip().split(":")[1].strip())
                logger.debug(f"Fraud score for {ip}: {score}")
                return score
        logger.warning(f"Couldn't find fraud score for {ip}")
        return None
    except Exception as e:
        logger.error(f"Error checking Scamalytics for {ip}: {str(e)}")
        return None

# --- New Google Sheets functions for Used IPs ---
def append_used_ip(ip, proxy):
    """Appends a new row to the Google Sheet for a used IP."""
    try:
        sheet = get_sheet()
        if sheet:
            sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
            logger.info(f"Appended used IP to Google Sheet: {ip}")
    except Exception as e:
        logger.error(f"Failed to append IP to Google Sheet: {e}")

def is_ip_used(ip):
    """Checks if an IP address exists in the Google Sheet."""
    try:
        sheet = get_sheet()
        if sheet:
            ips_in_sheet = sheet.col_values(1)
            return ip in ips_in_sheet
        return False
    except Exception as e:
        logger.error(f"Failed to check if IP is used in Google Sheet: {e}")
        return False # Fail safe

def remove_ip_from_sheet(ip):
    """Finds a row by IP and deletes it from the Google Sheet."""
    try:
        sheet = get_sheet()
        if not sheet: return False
        
        cell = sheet.find(ip, in_column=1)
        if cell:
            sheet.delete_rows(cell.row)
            logger.info(f"Deleted IP {ip} from Google Sheet at row {cell.row}")
            return True
        return False
    except gspread.exceptions.CellNotFound:
        logger.warning(f"IP {ip} not found in Google Sheet for deletion.")
        return False
    except Exception as e:
        logger.error(f"Error deleting IP {ip} from Google Sheet: {e}")
        return False

def list_used_ips():
    """Lists all records from the 'UsedIPs' Google Sheet."""
    try:
        sheet = get_sheet()
        if sheet:
            # gspread get_all_records() returns a list of dictionaries.
            # The admin template expects keys: 'IP', 'Proxy', 'Date'.
            # Ensure your Google Sheet has these headers in the first row.
            return sheet.get_all_records()
        return []
    except Exception as e:
        logger.error(f"Failed to list used IPs from Google Sheet: {e}")
        return []

def single_check_proxy(proxy_line):
    try:
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        logger.debug(f"Checking proxy: {proxy_line[:20]}...")
        
        ip = get_ip_from_proxy(proxy_line)
        if not ip: return None

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
    # This function remains, logging to the local SQLite DB
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO good_proxies (proxy) VALUES (?)", (proxy,))
        conn.commit()
    except Exception as e: logger.error(f"Error logging good proxy: {str(e)}")
    finally:
        if conn: conn.close()

def log_daily_check(good_count):
    # This function remains, logging to the local SQLite DB
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
    except Exception as e: logger.error(f"Error logging daily check: {str(e)}")
    finally:
        if conn: conn.close()


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    logger.info(f"Handling {request.method} request for /")
    
    if request.method == "POST":
        proxies_to_check = []
        # ... (code for reading proxies from file/text is unchanged) ...
        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            # ...
            proxies_to_check = all_lines[:PROXY_CHECK_HARD_LIMIT]
        elif 'proxytext' in request.form:
            # ...
            proxies_to_check = all_lines[:PROXY_CHECK_HARD_LIMIT]
        
        # Validate and deduplicate
        valid_proxies = list(set(p.strip() for p in proxies_to_check if p.strip() and len(p.split(':')) >= 4))
        
        if valid_proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy) for proxy in valid_proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        # [MODIFIED] Check against Google Sheet
                        used = is_ip_used(result["ip"])
                        results.append({"proxy": result["proxy"], "used": used})
                        log_good_proxy(result["proxy"]) # Still log to local DB
            
            good_count = len([r for r in results if not r['used']])
            log_daily_check(good_count)
            # ... (message generation is unchanged) ...
    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    """[MODIFIED] Tracks used proxy by sending it to Google Sheets."""
    logger.info("Tracking used proxy via Google Sheets")
    try:
        data = request.get_json()
        if data and "proxy" in data:
            proxy = data["proxy"]
            logger.info(f"Tracking proxy: {proxy[:20]}...")
            ip = get_ip_from_proxy(proxy)
            if ip:
                # Call the new Google Sheets function
                append_used_ip(ip, proxy)
            return jsonify({"status": "success"})
        return jsonify({"status": "error"}), 400
    except Exception as e:
        logger.error(f"Error tracking used proxy: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error"}), 500

@app.route("/delete-used-ip/<ip>")
def delete_used_ip_route(ip):
    """[MODIFIED] Deletes an IP from the Google Sheet."""
    logger.info(f"Deleting used IP from Google Sheet: {ip}")
    remove_ip_from_sheet(ip)
    return redirect(url_for("admin"))

@app.route("/admin")
def admin():
    logger.info("Loading admin panel")
    stats = {"total_checks": 0, "total_good": 0}
    logs = []
    daily_data = {}
    
    # Get stats from local SQLite database (this part is unchanged)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM check_logs")
        stats["total_checks"] = c.fetchone()[0]
        c.execute("SELECT SUM(good_count) FROM check_logs")
        stats["total_good"] = c.fetchone()[0] or 0
        c.execute("SELECT check_date, good_count FROM check_logs ORDER BY check_date DESC")
        for row in c.fetchall():
            logs.append(f"{row[0]},{row[1]} proxies")
            daily_data[row[0]] = row[1]
        conn.close()
    except Exception as e:
        logger.error(f"Error getting stats from local DB: {e}")

    # Generate graph (unchanged)
    if daily_data:
        # ... (graph generation logic) ...
        plt.savefig("static/proxy_stats.png")
        plt.close()

    # [MODIFIED] Get used IPs from Google Sheets
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
