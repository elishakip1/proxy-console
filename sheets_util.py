import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials

SCOPE = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

SHEET_NAME = "Used IP List"

def get_sheet():
    creds_dict = json.loads(os.environ.get("GOOGLE_CREDENTIALS"))
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
    client = gspread.authorize(creds)
    return client.open(SHEET_NAME).sheet1

def add_used_ip(ip, proxy):
    sheet = get_sheet()
    sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])

def is_ip_used_sheets(ip):
    sheet = get_sheet()
    ips = sheet.col_values(1)
    return ip in ips

def delete_used_ip_sheets(ip):
    sheet = get_sheet()
    records = sheet.get_all_records()
    for i, row in enumerate(records):
        if row.get("IP") == ip:
            sheet.delete_rows(i + 2)
            break

def list_used_ips_sheets():
    sheet = get_sheet()
    return sheet.get_all_records()