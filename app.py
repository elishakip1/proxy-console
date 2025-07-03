import os
import sys
import time
import logging
import traceback
from flask import Flask, render_template, jsonify, request, redirect, url_for
import concurrent.futures
import requests # For making HTTP requests to check proxies

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Environment variables (simplified for this example)
# In a real Digital Ocean deployment, you'd set these as environment variables.
# For local testing, you can uncomment and set values here, or use a .env file.
# os.environ['PORT'] = '5000' # Example for local testing
# os.environ['MAX_CONCURRENT_CHECKS'] = '10' # Max concurrent proxy checks

# Global storage for used proxies (in-memory for demonstration)
# In a production app, use a persistent database (e.g., Redis, PostgreSQL, etc.)
# This set will reset if the Flask app restarts.
USED_PROXIES = set()

# Get environment variables
def get_env_vars():
    """Get and log environment variables"""
    env_vars = {
        'PORT': os.environ.get('PORT', '5000'),
        'MAX_CONCURRENT_CHECKS': int(os.environ.get('MAX_CONCURRENT_CHECKS', '10')), # Max concurrent proxy checks
        'REDIRECT_DELAY_SECONDS': int(os.environ.get('REDIRECT_DELAY_SECONDS', '300')) # 5 minutes default
    }

    logger.info("Environment Variables:")
    for key, value in env_vars.items():
        logger.info(f"  {key}: {value}")

    return env_vars

env = get_env_vars()
PORT = int(env['PORT'])
MAX_CONCURRENT_CHECKS = env['MAX_CONCURRENT_CHECKS']
REDIRECT_DELAY_SECONDS = env['REDIRECT_DELAY_SECONDS']

# --- Proxy Checking Logic ---

def check_proxy(proxy_string, target_url="http://ip-api.com/json"):
    """
    Checks a single proxy.
    This is a basic example. A real proxy checker would:
    - Use a more robust target URL (e.g., one that returns IP + user-agent to detect proxy type)
    - Handle various error types (timeout, connection error, bad proxy response)
    - Parse real fraud scores if available from a service.
    """
    proxy_info = {
        "proxy": proxy_string,
        "is_valid": False,
        "fraud_score": -1, # -1 for unknown/error, 0 for good, >0 for bad
        "ip": None,
        "country": None,
        "error": None,
        "used": proxy_string in USED_PROXIES # Check if already marked as used
    }
    
    proxies = {
        "http": f"http://{proxy_string}",
        "https": f"http://{proxy_string}" # Assuming HTTP proxies can be used for HTTPS
    }

    try:
        # We use a short timeout to quickly identify bad proxies
        response = requests.get(target_url, proxies=proxies, timeout=5)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        # Basic check: if we get a country, assume it's somewhat working
        if data.get("status") == "success":
            proxy_info["is_valid"] = True
            proxy_info["fraud_score"] = 0 # Assume 0 for now if it works and returns basic info
            proxy_info["ip"] = data.get("query")
            proxy_info["country"] = data.get("country")
        else:
            proxy_info["error"] = f"API response status: {data.get('status')}"

    except requests.exceptions.Timeout:
        proxy_info["error"] = "Timeout"
    except requests.exceptions.ConnectionError:
        proxy_info["error"] = "Connection Error"
    except requests.exceptions.HTTPError as e:
        proxy_info["error"] = f"HTTP Error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        proxy_info["error"] = f"Request Exception: {str(e)}"
    except Exception as e:
        proxy_info["error"] = f"An unexpected error occurred: {str(e)}"

    if proxy_info["error"]:
        logger.warning(f"Proxy {proxy_string} failed: {proxy_info['error']}")
    else:
        logger.info(f"Proxy {proxy_string} is {'valid' if proxy_info['is_valid'] else 'invalid'}")

    return proxy_info

def parse_proxies(raw_proxies):
    """Parses a string of proxies into a list, one per line."""
    if not raw_proxies:
        return []
    # Filter out empty lines and strip whitespace
    return [proxy.strip() for proxy in raw_proxies.split('\n') if proxy.strip()]

# --- Flask Routes ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main page with the proxy input form."""
    return render_template('index.html', results=None, message=None, redirect_delay=REDIRECT_DELAY_SECONDS)

@app.route('/', methods=['POST'])
def check_proxies_post():
    """Handles the form submission for proxy checking."""
    proxies_to_check = []
    message = None

    # Handle file upload
    if 'proxyfile' in request.files and request.files['proxyfile'].filename != '':
        file = request.files['proxyfile']
        try:
            file_content = file.read().decode('utf-8')
            proxies_to_check = parse_proxies(file_content)
            logger.info(f"Received {len(proxies_to_check)} proxies from file upload.")
        except Exception as e:
            logger.error(f"Error reading uploaded file: {e}")
            message = "Error reading uploaded file. Please ensure it's a plain text file."
            return render_template('index.html', results=None, message=message, redirect_delay=REDIRECT_DELAY_SECONDS)
    # Handle pasted text
    elif 'proxytext' in request.form and request.form['proxytext'].strip() != '':
        raw_text = request.form['proxytext']
        proxies_to_check = parse_proxies(raw_text)
        logger.info(f"Received {len(proxies_to_check)} proxies from text area.")
    else:
        message = "No proxies provided. Please paste them or upload a file."
        return render_template('index.html', results=None, message=message, redirect_delay=REDIRECT_DELAY_SECONDS)

    if not proxies_to_check:
        message = "No valid proxies found in your input."
        return render_template('index.html', results=None, message=message, redirect_delay=REDIRECT_DELAY_SECONDS)

    # Limit the number of proxies to check to prevent abuse and large processing times
    if len(proxies_to_check) > 50:
        message = "Too many proxies provided. Maximum 50 proxies are allowed at once."
        proxies_to_check = proxies_to_check[:50] # Truncate if too many
        logger.warning(f"Truncated proxy list to 50 entries.")

    checked_results = []
    start_time = time.time()
    logger.info(f"Starting proxy checks for {len(proxies_to_check)} proxies...")

    # Use ThreadPoolExecutor for concurrent checking
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS) as executor:
        # Map the check_proxy function to each proxy_string
        future_to_proxy = {executor.submit(check_proxy, p): p for p in proxies_to_check}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy_string = future_to_proxy[future]
            try:
                result = future.result()
                checked_results.append(result)
            except Exception as exc:
                logger.error(f"Proxy {proxy_string} generated an exception: {exc}")
                checked_results.append({"proxy": proxy_string, "is_valid": False, "fraud_score": -1, "error": str(exc), "used": proxy_string in USED_PROXIES})

    end_time = time.time()
    logger.info(f"Finished checking {len(checked_results)} proxies in {end_time - start_time:.2f} seconds.")

    # Filter for good proxies (fraud_score 0)
    good_proxies = [r for r in checked_results if r['is_valid'] and r['fraud_score'] == 0]
    
    # Sort good proxies to ensure consistent display
    good_proxies.sort(key=lambda x: x['proxy'])

    return render_template('index.html', results=good_proxies, message=message, redirect_delay=REDIRECT_DELAY_SECONDS)

@app.route('/track-used', methods=['POST'])
def track_used_proxy():
    """Endpoint to mark a proxy as 'used'."""
    data = request.get_json()
    proxy = data.get('proxy')
    if proxy:
        USED_PROXIES.add(proxy)
        logger.info(f"Proxy marked as used: {proxy}")
        return jsonify({"status": "success", "message": f"Proxy '{proxy}' marked as used."}), 200
    return jsonify({"status": "error", "message": "No proxy provided."}), 400

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return "OK", 200

if __name__ == '__main__':
    logger.info("Starting Proxy Checker Application")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Running on port: {PORT}")
    logger.info(f"Max concurrent checks: {MAX_CONCURRENT_CHECKS}")

    # Ensure templates directory exists
    if not os.path.exists('templates'):
        os.makedirs('templates')

    app.run(host='0.0.0.0', port=PORT, debug=False) # Set debug=True for development, False for production
