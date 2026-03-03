# ================= main.py =================
import subprocess
import shlex
import sys
import json
import socket
import ssl  # Native SSL library
import re
import asyncio
import time
import copy
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Body, Query
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, or_
from sqlalchemy.orm import relationship, Session
from pydantic import BaseModel, EmailStr, field_validator

# External Libraries
import whois
import dns.resolver
import requests
import urllib3
from fastapi_mail import FastMail, MessageSchema

# PDF Generation Libraries
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pdfencrypt import StandardEncryption

# CHART Libraries
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# Local imports
import auth
from database import Base, engine, get_db
from fastapi.middleware.cors import CORSMiddleware
from monitor import SmartDetector, MonitorState, monitoring_loop
from urllib.parse import urlparse

# Import Models
from models import User, LoginAttempt, Domain, Monitor, Incident, AlertRule, AlertHistory

# Import Schemas for Alerts
try:
    from alerts import AlertRuleCreate, AlertRuleResponse, AlertHistoryResponse
except ImportError:
    class AlertRuleCreate(BaseModel):
        name: str
        type: str
        target_id: int = None
        condition: str
        threshold: str = None
        severity: str = "warning"
        channel: str = "email"

    class AlertRuleResponse(AlertRuleCreate):
        id: int
        user_id: int
        created_at: datetime
        is_active: bool
        
        class Config:
            from_attributes = True
            
    class AlertHistoryResponse(BaseModel):
        id: int
        rule_id: Optional[int]
        time: str
        channel: str
        status: str
        recipient: str
        message: Optional[str] = None
        
        class Config:
            from_attributes = True

from io import BytesIO
from fastapi.responses import StreamingResponse

# Suppress SSL warnings for internal checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create tables
Base.metadata.create_all(bind=engine)

# ================= FASTAPI APP =================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

state = MonitorState()

# ================= SCHEMAS =================
class RegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    username: str
    password: str

class ForgotPasswordSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class StartRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str):
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v

# Report Schemas
class GlobalReportRequest(BaseModel):
    password: str

class DomainAddRequest(BaseModel):
    domain: str

# ================= AUTHENTICATION ROUTES =================
@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    return auth.register_user(db, User, data.username, data.email, data.password)

@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    return auth.login_user(db, User, LoginAttempt, data.username, data.password)

@app.post("/forgot-password")
async def forgot_password(data: ForgotPasswordSchema, db: Session = Depends(get_db)):
    return await auth.forgot_password(db, User, data.email)

@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    return auth.reset_password(db, User, data.token, data.new_password)

@app.get("/")
def read_root():
    return {"version": "17.1", "model": "CyberGuard-Domain-Intel"}

# ================= DOMAIN TRACKING LOGIC & FIXES =================

# --- HYBRID SSL FETCHING FUNCTION (Native + SSL Labs API) ---
def _get_cert_via_ssl_module(domain_name):
    """
    Fetches SSL certificate.
    1. Tries Native Connection (Fastest, Standard).
    2. Falls back to SSL Labs API if Native fails.
    """
    
    # --- HELPER: SSL Labs API Fallback ---
    def get_from_ssl_labs(host):
        try:
            # Endpoint for host info
            url = f"https://api.ssllabs.com/v1/info?host={host}"
            headers = {'User-Agent': 'Mozilla/5.0 (CyberGuard/1.0)'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Normalize status
                status = "Unknown"
                if data.get("valid") is True:
                    status = "Valid"
                elif data.get("valid") is False:
                    status = "Invalid"
                
                # Extract Issuer
                issuer = "Unknown"
                if "issuer_organization" in data and data["issuer_organization"]:
                    issuer = data["issuer_organization"]
                elif "issuer_name" in data:
                    issuer = data["issuer_name"]
                
                # Extract Expiration (API returns ISO 8601)
                expires = data.get("expires", "Unknown")
                
                return {
                    "status": status,
                    "issuer": issuer,
                    "expires": expires
                }
        except Exception as e:
            print(f"[SSL LABS ERROR] {e}")
            return None

    # --- MAIN SSL FETCH LOGIC ---
    def _fetch_cert(target_ip_or_domain):
        try:
            # Clean domain (remove http:// etc)
            target = target_ip_or_domain.replace("https://", "").replace("http://", "").split("/")[0]
            
            # Create a modern SSL Context
            # PROTOCOL_TLS_CLIENT is best for modern browsers/servers
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create a standard IPv4 Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)  # Increased timeout for slow networks
            
            # 1. Connect to the server on port 443
            sock.connect((target, 443))
            
            # 2. Wrap the socket with SSL
            ssock = context.wrap_socket(sock, server_hostname=target)
            
            # 3. FORCE the handshake to complete
            ssock.do_handshake()
            
            # 4. Get the certificate
            cert = ssock.getpeercert()
            
            # Close connection
            ssock.close()
            
            if not cert:
                raise ValueError("No Cert Data")

            # Extract Issuer
            issuer = "Unknown"
            try:
                for item in cert.get('issuer', []):
                    for sub_item in item:
                        if sub_item[0] == 'organizationName':
                            issuer = sub_item[1]
                            break
                    if issuer != "Unknown": break
            except:
                pass 

            if issuer == "Unknown":
                try:
                    for item in cert.get('issuer', []):
                        for sub_item in item:
                            if sub_item[0] == 'commonName':
                                issuer = sub_item[1]
                                break
                        if issuer != "Unknown": break
                except:
                    pass

            not_after = cert.get('notAfter')
            
            # --- ROBUST DATE PARSING ---
            status = "Unknown"
            formatted_expiry = "Unknown"
            
            if not_after:
                # List of common SSL date formats
                date_formats = [
                    "%b %d %H:%M:%S %Y %Z", # Jan 01 12:00:00 2024 GMT
                    "%b %d %H:%M:%S %Y",    # Jan 01 12:00:00 2024 (some certs omit Z)
                    "%Y-%m-%dT%H:%M:%SZ",    # 2024-01-01T12:00:00Z (ISO 8601)
                    "%Y-%m-%dT%H:%M:%S.%fZ", # 2024-01-01T12:00:00.000Z
                    "%Y-%m-%d"                # 2024-01-01
                ]
                
                parsed_date = None
                for fmt in date_formats:
                    try:
                        parsed_date = datetime.strptime(not_after.strip(), fmt)
                        break # Stop if we successfully parse
                    except ValueError:
                        continue
                
                if parsed_date:
                    if parsed_date < datetime.utcnow():
                        status = "Expired"
                    else:
                        status = "Valid"
                    # Return ISO format string to frontend to be safe and standard
                    formatted_expiry = parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ") 
                else:
                    status = "Invalid Date"
                    formatted_expiry = not_after # Pass raw string if we can't parse
            else:
                status = "No Expiry"

            return {
                "status": status,
                "issuer": issuer,
                "expires": formatted_expiry
            }
            
        except Exception as e:
            # FALLBACK TO SSL LABS API IF NATIVE FAILS
            print(f"[NATIVE SSL FAILED FOR {target_ip_or_domain}, trying SSL Labs API...")
            api_result = get_from_ssl_labs(target_ip_or_domain)
            
            if api_result:
                return api_result
            else:
                return {"status": "Error", "issuer": "Unknown", "expires": "Unknown"}

    return _fetch_cert(domain_name)

# --- RDAP / WHOIS HELPER ---
def _get_rdap_info_ultra(domain_name):
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'Accept': 'application/rdap+json', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
        if response.status_code == 200:
            data = response.json()
            info = {"registrar": None, "created": None, "expires": None}
            events = data.get("events", [])
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                if "expir" in action: info["expires"] = date_val
                if "regist" in action or "creat" in action: info["created"] = date_val
            entities = data.get("entities", [])
            for entity in entities:
                roles = [str(r).lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray")
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]; break
                    if not info["registrar"]: info["registrar"] = "Redacted"
            return info, "RDAP"
        else: 
            return {"registrar": "Error", "created": None, "expires": None}, "Error"
    except Exception as e: 
        return {"registrar": f"Error: {str(e)[:20]}", "created": None, "expires": None}, "Error"

# --- DNS HELPER ---
def get_dns_records(domain):
    """Resolves DNS records for a domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            results[rtype] = []
            
    return results

# --- SCAN LOGIC (Background Task) ---
def run_domain_scan_logic(domain_name):
    """Runs the blocking scan operations."""
    print(f"[SCAN START] Scanning {domain_name}...")
    
    # 1. Get DNS
    dns_data = get_dns_records(domain_name)
    
    # 2. Get SSL (Using the Hybrid Function)
    ssl_data = _get_cert_via_ssl_module(domain_name)
    
    # 3. Get WHOIS (Using the RDAP function)
    whois_data, _ = _get_rdap_info_ultra(domain_name)
    
    # 4. Prepare Database Payloads
    return {
        "dns": json.dumps(dns_data),
        "ssl": json.dumps(ssl_data),
        "whois": json.dumps(whois_data)
    }

def check_domain_expiry_alerts(domain: Domain, days_remaining: int, db: Session):
    """
    Checks if any active domain alert rules are triggered based on expiration time.
    """
    try:
        rules = db.query(AlertRule).filter(
            AlertRule.user_id == domain.user_id,
            AlertRule.type == "domain",
            AlertRule.is_active == True
        ).all()

        for rule in rules:
            if rule.target_id is not None and rule.target_id != domain.id:
                continue

            triggered = False
            message = ""

            if rule.condition == "domain_expiring":
                threshold_str = rule.threshold.strip() if rule.threshold else ""
                match = re.search(r'(\d+)', threshold_str)
                if not match:
                    print(f"[ALERT DEBUG] Could not find number in threshold: {threshold_str}")
                    continue
                
                limit = int(match.group(1))
                operator = '>'
                if '>=' in threshold_str: operator = '>='
                elif '>' in threshold_str: operator = '>'
                elif '<=' in threshold_str: operator = '<='
                elif '<' in threshold_str: operator = '<'
                else: operator = '<' 

                if operator == '>=' and days_remaining >= limit: triggered = True
                elif operator == '>' and days_remaining > limit: triggered = True
                elif operator == '<=' and days_remaining <= limit: triggered = True
                elif operator == '<' and days_remaining < limit: triggered = True

            if triggered:
                recent_alert = db.query(AlertHistory).filter(
                    AlertHistory.user_id == domain.user_id,
                    AlertHistory.source_id == domain.id,
                    AlertHistory.rule_id == rule.id,
                    AlertHistory.triggered_at > datetime.utcnow() - timedelta(hours=1)
                ).first()

                if not recent_alert:
                    message = (f"Domain Expiring Alert: {domain.domain_name} expires in {days_remaining} days. "
                               f"(Threshold: {rule.threshold})")

                    print(f"[DOMAIN ALERT TRIGGERED] {message}")

                    new_alert = AlertHistory(
                        user_id=domain.user_id,
                        rule_id=rule.id,
                        source_type="domain",
                        source_id=domain.id,
                        message=message,
                        severity=rule.severity,
                        channel=rule.channel,
                        status="sent"
                    )
                    db.add(new_alert)
                    db.commit()

    except Exception as e:
        print(f"[DOMAIN ALERT ERROR] {e}")
        db.rollback()

# ================= DOMAIN API ROUTES =================

# --- 1. LIST DOMAINS ---
@app.get("/domain/list")
def list_domains(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns list of domains for the logged-in user."""
    domains = db.query(Domain).filter(Domain.user_id == current_user.id).all()
    
    # Format for frontend
    response = []
    for d in domains:
        response.append({
            "id": d.id,
            "domain_name": d.domain_name,
            "security_score": d.security_score,
            "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
            "ssl_status": json.loads(d.ssl_data).get("status") if d.ssl_data else "Unknown"
        })
    return response

# --- 2. ADD DOMAIN (FIXED) ---
@app.post("/domain/add")
async def add_domain(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(auth.get_current_user)
):
    """
    Adds a new domain and performs an immediate scan.
    Accepts raw string body (e.g., "google.com") to match frontend.
    Uses Hybrid SSL Fetcher (Native + SSL Labs API).
    """
    # Read raw body to get simple string domain
    body = await request.body()
    domain_name = body.decode("utf-8").strip().strip('"\'')
    
    # Basic Validation
    if not domain_name:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    
    # Clean the domain (remove http/https if user typed it)
    clean_domain = domain_name.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    # Check duplicates
    existing = db.query(Domain).filter(Domain.domain_name == clean_domain, Domain.user_id == current_user.id).first()
    if existing:
        return {"message": "Domain already tracked", "id": existing.id}

    # Create Domain Record (Empty initially)
    new_domain = Domain(
        domain_name=clean_domain,
        user_id=current_user.id,
        security_score=0,
        ssl_data="{}",
        whois_data="{}",
        dns_data="{}",
        manual_data="{}"
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    # Run Scan in background to avoid blocking
    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, clean_domain)
        
        # Update DB with results
        new_domain.dns_data = scan_results["dns"]
        new_domain.ssl_data = scan_results["ssl"]
        new_domain.whois_data = scan_results["whois"]
        new_domain.last_scanned = datetime.utcnow()
        
        # Calculate a rough score based on status
        ssl_info = json.loads(scan_results["ssl"])
        new_domain.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        # Don't fail the add, just leave data empty if scan fails
        
    return {"message": "Domain added and scanned", "id": new_domain.id}

# --- 3. GET DOMAIN DETAILS ---
@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns detailed info for a specific domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Parse JSON data
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except:
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    return {
        "id": d.id,
        "domain_name": d.domain_name,
        "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
        "ssl_status": ssl_data.get("status"),
        "ssl_issuer": ssl_data.get("issuer"),
        "ssl_expires": ssl_data.get("expires"),
        "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"),
        "registrar": whois_data.get("registrar"),
        "dns_records": dns_data,
        "manual_data": manual_data
    }

# --- 4. RE-SCAN DOMAIN ---
@app.post("/domain/scan/{id}")
async def rescan_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Forces a rescan of a domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, d.domain_name)
        
        d.dns_data = scan_results["dns"]
        d.ssl_data = scan_results["ssl"]
        d.whois_data = scan_results["whois"]
        d.last_scanned = datetime.utcnow()
        
        # Update score
        ssl_info = json.loads(scan_results["ssl"])
        d.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
        return {"message": "Scan successful"}
    except Exception as e:
        print(f"[RESCAN ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# --- 5. DELETE DOMAIN ---
@app.delete("/domain/{id}")
def delete_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    db.delete(d)
    db.commit()
    return {"message": "Deleted"}

# --- 6. UPDATE MANUAL DATA ---
@app.post("/domain/update-manual/{id}")
def update_manual_domain_data(id: int, data: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Updates manual asset data."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Merge new data with existing manual data
    try:
        existing_manual = json.loads(d.manual_data) if d.manual_data else {}
    except:
        existing_manual = {}
        
    updated_manual = {**existing_manual, **data}
    d.manual_data = json.dumps(updated_manual)
    d.last_scanned = datetime.utcnow() # Update scan time to show 'fresh' data
    
    db.commit()
    return {"message": "Manual data updated"}

# ================= ALERTS API ROUTES =================
@app.get("/alerts/rules", response_model=List[AlertRuleResponse])
def get_alert_rules(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    return db.query(AlertRule).filter(AlertRule.user_id == current_user.id).all()

@app.post("/alerts/rules", response_model=AlertRuleResponse)
def create_alert_rule(rule: AlertRuleCreate, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    new_rule = AlertRule(
        user_id=current_user.id,
        name=rule.name,
        type=rule.type,
        target_id=rule.target_id,
        condition=rule.condition,
        threshold=rule.threshold,
        severity=rule.severity,
        channel=rule.channel
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return new_rule

@app.delete("/alerts/rules/{rule_id}")
def delete_alert_rule(rule_id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id, AlertRule.user_id == current_user.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Deleted"}

@app.get("/alerts/history", response_model=List[AlertHistoryResponse])
def get_alert_history(limit: int = 50, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    history = db.query(AlertHistory).filter(AlertHistory.user_id == current_user.id).order_by(AlertHistory.triggered_at.desc()).limit(limit).all()
    
    result = []
    for h in history:
        data = {
            "id": h.id,
            "rule_id": h.rule_id,
            "time": h.triggered_at.isoformat() if h.triggered_at else "",
            "channel": h.channel,
            "status": h.status,
            "recipient": "User", 
            "severity": h.severity,
            "message": h.message
        }
        result.append(AlertHistoryResponse(**data))
    return result

# ================= GLOBAL REPORT GENERATION (MONITORING) =================

# --- Custom Colors ---
PDF_TITLE_COLOR = colors.HexColor("#0f172a")
PDF_TEXT_COLOR = colors.HexColor("#1f2937")
PDF_MUTED_COLOR = colors.HexColor("#4b5563")

CYBER_CYAN = colors.HexColor("#06b6d4")
DARK_BG = colors.HexColor("#0f172a")
LIGHT_BG = colors.HexColor("#1e293b")
STATUS_GREEN = colors.HexColor("#10b981")
STATUS_RED = colors.HexColor("#ef4444")
STATUS_ORANGE = colors.HexColor("#f59e0b")
WHITE = colors.white
GRAY_TEXT = colors.HexColor("#94a3b8")

def create_global_pie_chart(data):
    drawing = Drawing(400, 200)
    pc = Pie()
    pc.x = 120; pc.y = 25; pc.width = 150; pc.height = 150
    pc.data = [data.get('up', 0), data.get('down', 0), data.get('warning', 0)]
    pc.labels = ['Operational', 'Down', 'Warning']
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices[2].fillColor = STATUS_ORANGE
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    title = String(200, 180, 'Global System Status', fontName='Helvetica-Bold', fontSize=14, fillColor=PDF_TITLE_COLOR, textAnchor='middle')
    drawing.add(pc); drawing.add(title)
    return drawing

def create_mini_pie(healthy, unhealthy):
    drawing = Drawing(100, 100)
    if healthy == 0 and unhealthy == 0: return drawing
    pc = Pie()
    pc.x = 15; pc.y = 10; pc.width = 70; pc.height = 70
    pc.data = [healthy, unhealthy]
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    drawing.add(pc)
    return drawing

def analyze_subdomain(target, status, history):
    total_checks = len(history)
    valid_latency = [h for h in history if h > 0]
    healthy_count = len([h for h in history if h > 0 and h < 3000])
    unhealthy_count = total_checks - healthy_count
    uptime_pct = (healthy_count / total_checks * 100) if total_checks > 0 else 0
    avg_lat = sum(valid_latency) / len(valid_latency) if valid_latency else 0
    max_lat = max(valid_latency) if valid_latency else 0
    min_lat = min(valid_latency) if valid_latency else 0
    
    is_down = "DOWN" in status or "ERROR" in status or "REFUSED" in status or "404" in status
    is_slow = "WARNING" in status or "TIMEOUT" in status or avg_lat > 1500
    is_healthy = not is_down and not is_slow
    short_url = target.replace("https://", "").replace("http://", "")
    
    if is_down:
        desc = (f"<b>Critical Alert:</b> <font color='#dc2626'><b>{short_url}</b></font> is <b>DOWN</b>. "
                f"Last check: <i>{status}</i>. {unhealthy_count} failures.")
        status_color = STATUS_RED
        status_label = "CRITICAL"
    elif is_slow:
        desc = (f"<b>Performance Warning:</b> <font color='#d97706'><b>{short_url}</b></font> high latency. "
                f"Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_ORANGE
        status_label = "WARNING"
    else:
        desc = (f"<b>Operational:</b> <font color='#059669'><b>{short_url}</b></font> is healthy. "
                f"Uptime: <b>{uptime_pct:.1f}%</b>, Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_GREEN # Fixed: was status_green (undefined)
        status_label = "OPERATIONAL"

    return {
        "desc": desc, "uptime": uptime_pct, "avg": avg_lat, "min": min_lat, "max": max_lat,
        "healthy": healthy_count, "unhealthy": unhealthy_count,
        "status_color": status_color, "status_label": status_label
    }

def generate_global_monitoring_pdf(password: str, state_data: dict):
    """Generates a secure, detailed PDF report for Uptime Monitoring."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=20, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=10)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=10, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=16, textColor=WHITE, backColor=DARK_BG, borderPadding=10, spaceBefore=15, spaceAfter=10)
    analysis_style = ParagraphStyle('Analysis', parent=styles['Normal'], fontSize=9, textColor=PDF_TEXT_COLOR, alignment=TA_JUSTIFY, spaceBefore=10, spaceAfter=15, leading=14)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"Global Monitoring Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(Paragraph(f"<font color='red'><b>SECURED DOCUMENT - PASSWORD PROTECTED</b></font>", ParagraphStyle('Secure', fontSize=9, alignment=TA_CENTER, spaceAfter=20)))

    targets = state_data.get("targets", [])
    current_statuses = state_data.get("current_statuses", {})
    histories = state_data.get("histories", {})

    up_count = 0; down_count = 0; warning_count = 0
    analysis_results = []

    for target in targets:
        status = current_statuses.get(target, "Unknown")
        history = histories.get(target, [])
        res = analyze_subdomain(target, status, history)
        analysis_results.append({"target": target, "data": res})
        if res['status_label'] == "OPERATIONAL": up_count += 1
        elif res['status_label'] == "CRITICAL": down_count += 1
        else: warning_count += 1

    elements.append(Paragraph("Executive Summary", header_style))
    summary_data = [["Total Targets", "Operational", "Down", "Warnings"], [str(len(targets)), str(up_count), str(down_count), str(warning_count)]]
    t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), GRAY_TEXT),
        ('TEXTCOLOR', (1, 1), (1, 1), STATUS_GREEN),
        ('TEXTCOLOR', (2, 1), (2, 1), STATUS_RED),
        ('TEXTCOLOR', (3, 1), (3, 1), STATUS_ORANGE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 18),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b"))
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 20))

    pie_data = {'up': up_count, 'down': down_count, 'warning': warning_count}
    if any(v > 0 for v in pie_data.values()): elements.append(create_global_pie_chart(pie_data))
    elements.append(PageBreak())

    elements.append(Paragraph("Detailed Subdomain Analysis", header_style))
    elements.append(Spacer(1, 10))

    for item in analysis_results:
        target = item['target']
        res = item['data']
        subdomain_elements = []
        header_table = Table([[Paragraph(f"{res['status_label']}", ParagraphStyle('H', fontSize=10, textColor=WHITE, alignment=TA_CENTER)), Paragraph(f"<b>{target}</b>", ParagraphStyle('Url', fontSize=10, textColor=WHITE))]], colWidths=[1*inch, 5.5*inch])
        
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), res['status_color']),
            ('BACKGROUND', (1, 0), (1, 0), LIGHT_BG),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8)
        ]))
        subdomain_elements.append(header_table)
        subdomain_elements.append(Spacer(1, 5))
        subdomain_elements.append(Paragraph(res['desc'], analysis_style))
        mini_chart = create_mini_pie(res['healthy'], res['unhealthy'])
        metric_data = [["Uptime", f"{res['uptime']:.1f}%"], ["Avg Latency", f"{res['avg']:.0f} ms"], ["Max Latency", f"{res['max']:.0f} ms"], ["Checks", f"{res['healthy'] + res['unhealthy']}"]]
        t_metrics = Table(metric_data, colWidths=[1.5*inch, 1*inch])
        
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
            ('TEXTCOLOR', (0, 0), (0, -1), PDF_MUTED_COLOR),
            ('TEXTCOLOR', (1, 0), (1, -1), PDF_TEXT_COLOR),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.2, colors.HexColor("#d1d5db")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5)
        ]))
        content_layout = Table([[t_metrics, mini_chart]], colWidths=[3*inch, 3.5*inch])
        
        content_layout.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (1,0), (1,0), 0)
        ]))
        subdomain_elements.append(content_layout)
        subdomain_elements.append(Spacer(1, 20))
        line = Table([['']], colWidths=[6.5*inch])
        line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.HexColor("#e5e7eb"))]))
        subdomain_elements.append(line)
        subdomain_elements.append(Spacer(1, 10))
        elements.append(KeepTogether(subdomain_elements))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/monitoring/global-report")
async def download_global_monitoring_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user)):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        state_data = {
            "targets": list(state.targets),
            "current_statuses": dict(state.current_statuses),
            "histories": {k: list(v) for k, v in state.histories.items()}
        }
        pdf_buffer = generate_global_monitoring_pdf(data.password, state_data)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=cyberguard_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to generate report: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= SINGLE DOMAIN REPORT GENERATION =================
# ================= SINGLE DOMAIN REPORT GENERATION (UPDATED) =================

def formatDate(date_str):
    if not date_str: return "N/A"
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%B %d, %Y")
    except:
        return date_str

# NEW HELPER FOR ACCURATE INFORMATION
def get_field_value(field_name, manual_data, whois_data, dns_data):
    """
    Intelligently determines the value for a field by checking:
    1. Manual Input (Highest Priority)
    2. WHOIS/RDAP Data
    3. DNS Heuristics (Guessing from NS records)
    """
    
    # --- REGISTRAR LOGIC ---
    if field_name == "Registrar":
        if manual_data.get("registrar"):
            return manual_data.get("registrar")
        if whois_data.get("registrar"):
            reg = whois_data.get("registrar")
            return reg if reg != "Redacted" else "Private / Redacted"
        return "Unknown"

    # --- HOSTING PROVIDER LOGIC (Smart Guess) ---
    if field_name == "Hosting Provider":
        if manual_data.get("hostingProvider"):
            return manual_data.get("hostingProvider")
        
        # Heuristic: Guess Hosting from NS records
        if dns_data and "NS" in dns_data and len(dns_data["NS"]) > 0:
            ns = str(dns_data["NS"][0]).lower()
            if "aws" in ns: return "Amazon Web Services (AWS)"
            if "azure" in ns or "cloudapp" in ns: return "Microsoft Azure"
            if "google" in ns: return "Google Cloud (GCP)"
            if "cloudflare" in ns: return "Cloudflare"
            if "bluehost" in ns: return "Bluehost"
            if "godaddy" in ns: return "GoDaddy"
            if "hostgator" in ns: return "HostGator"
            if "digitalocean" in ns: return "DigitalOcean"
            if "heroku" in ns: return "Heroku"
            if "namecheap" in ns: return "Namecheap"
        
        return "Unknown (Set in Manual Asset)"

    # --- DNS PROVIDER LOGIC (Smart Guess) ---
    if field_name == "DNS Provider":
        if manual_data.get("dnsProvider"):
            return manual_data.get("dnsProvider")

        if dns_data and "NS" in dns_data and len(dns_data["NS"]) > 0:
            ns = dns_data["NS"][0].lower()
            if "aws" in ns: return "AWS Route 53"
            if "cloudflare" in ns: return "Cloudflare DNS"
            if "azure" in ns: return "Azure DNS"
            if "google" in ns: return "Google Cloud DNS"
            if "godaddy" in ns: return "GoDaddy DNS"
            
            # Fallback: Just return the NS server if unknown
            return dns_data["NS"][0]
            
        return "Unknown"

    # --- DEFAULT LOGIC ---
    return manual_data.get(field_name, "Not Set")

def generate_single_domain_pdf(domain_id: int, db: Session, password: str):
    """Generates a detailed PDF for a single specific domain."""
    d = db.query(Domain).filter(Domain.id == domain_id).first()
    if not d: raise HTTPException(status_code=404, detail="Domain not found")

    # Robust JSON parsing
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except (json.JSONDecodeError, TypeError):
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72, 
                            encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=32, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=30)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=20, textColor=WHITE, backColor=DARK_BG, spaceBefore=20, spaceAfter=15, 
                                  borderPadding=12, alignment=TA_CENTER, borderWidth=1, borderColor=CYBER_CYAN, borderRadius=6)
    section_title_style = ParagraphStyle('SectionTitle', parent=styles['Heading3'], fontSize=16, textColor=PDF_TITLE_COLOR, spaceBefore=25, spaceAfter=12, leading=20)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')

    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"<b>Domain Intelligence Report</b>", subtitle_style))
    
    status_color = STATUS_GREEN if ssl_data.get("status") == "Valid" else STATUS_RED
    status_txt = ssl_data.get("status", "Unknown").upper()
    
    exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
    risk_txt = "Low"
    if exp_date_str:
        try:
            exp_dt = datetime.strptime(exp_date_str.split('T')[0], "%Y-%m-%d")
            days = (exp_dt - datetime.utcnow()).days
            if days < 0: risk_txt = "Expired"
            elif days < 30: risk_txt = "Critical"
        except: pass

    domain_header_data = [
        [Paragraph(f"<b>{d.domain_name}</b>", ParagraphStyle('DH', fontSize=18, textColor=WHITE)), 
         Paragraph(f"<b>{status_txt}</b>", ParagraphStyle('DHS', fontSize=14, textColor=WHITE, alignment=TA_RIGHT))]
    ]
    dh_table = Table(domain_header_data, colWidths=[4*inch, 2*inch])
    dh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(dh_table)
    elements.append(Spacer(1, 20))

    # --- USING SMART HELPER FOR ACCURATE DATA ---
    vital_data = [
        [Paragraph("Registrar", label_style), Paragraph(get_field_value("Registrar", manual_data, whois_data, dns_data), body_style)],
        [Paragraph("Risk Level", label_style), Paragraph(f"<font color='{status_color.hexval() if hasattr(status_color, 'hexval') else '#000'}'><b>{risk_txt}</b></font>", body_style)],
        [Paragraph("Expiration", label_style), Paragraph(formatDate(exp_date_str) if exp_date_str else "Unknown", body_style)],
        [Paragraph("SSL Issuer", label_style), Paragraph(ssl_data.get("issuer", "Unknown"), body_style)]
    ]
    vital_table = Table(vital_data, colWidths=[1.8*inch, 4*inch])
    vital_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,1), 10),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(vital_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Ownership & Infrastructure", section_title_style))
    
    # --- UPDATED OWNER DATA SECTION ---
    owner_data = [
        [Paragraph("Primary Owner", label_style), Paragraph(manual_data.get("primaryOwner", "Not Set"), body_style)],
        [Paragraph("Department", label_style), Paragraph(manual_data.get("department", "Not Set"), body_style)],
        [Paragraph("Purpose", label_style), Paragraph(manual_data.get("purpose", "Unknown").upper(), body_style)],
        [Paragraph("DNS Provider", label_style), Paragraph(get_field_value("DNS Provider", manual_data, whois_data, dns_data), body_style)],
        [Paragraph("Hosting Provider", label_style), Paragraph(get_field_value("Hosting Provider", manual_data, whois_data, dns_data), body_style)]
    ]
    
    owner_table = Table(owner_data, colWidths=[1.8*inch, 4*inch])
    owner_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(owner_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Security Compliance", section_title_style))
    sec_checklist = manual_data.get("security", {})
    sec_data = [
        [Paragraph("Registrar Lock", label_style), Paragraph("Active" if sec_checklist.get('lock') else "Inactive", body_style)],
        [Paragraph("MFA Enabled", label_style), Paragraph("Yes" if sec_checklist.get('mfa') else "No", body_style)],
        [Paragraph("DNSSEC Enabled", label_style), Paragraph("Yes" if sec_checklist.get('dnssec') else "No", body_style)],
    ]
    sec_table = Table(sec_data, colWidths=[1.8*inch, 4*inch])
    sec_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(sec_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("DNS Infrastructure", section_title_style))
    if dns_data:
        for r_type, records in dns_data.items():
            if records:
                elements.append(Paragraph(f"<b>{r_type} Records ({len(records)})</b>", ParagraphStyle('DNSHead', fontSize=12, textColor=CYBER_CYAN, spaceAfter=6)))
                for rec in records:
                    elements.append(Paragraph(f"• {rec}", body_style))
                elements.append(Spacer(1, 10))
    else:
        elements.append(Paragraph("No DNS records found.", body_style))
    
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("Audit Log", section_title_style))
    notes = manual_data.get("notes", [])
    if notes:
        for note in notes:
            date = note.get('date', '')[:10]
            txt = note.get('text', '')
            elements.append(Paragraph(f"<b>{date}:</b> {txt}", body_style))
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph("No audit logs available.", body_style))

    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by CyberGuard AI", ParagraphStyle('Footer', fontSize=9, textColor=GRAY_TEXT, alignment=TA_CENTER)))

    doc.build(elements)
    buffer.seek(0)
    return buffer
    return buffer

@app.post("/domain/report/{id}")
async def download_single_domain_report(
    id: int, 
    data: GlobalReportRequest, 
    current_user: User = Depends(auth.get_current_user), 
    db: Session = Depends(get_db)
):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        pdf_buffer = generate_single_domain_pdf(id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Single Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= OLD GLOBAL DOMAIN REPORT =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual.get("expirationDate")
            if exp_date_str:
                try:
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    if (exp_date - datetime.utcnow()).days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 2.0*inch, 1.5*inch])
        
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{d.domain_name}</b></font>"
            status_text = f"<font color='white'>{ssl.get('status', 'Unknown')}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[4*inch, 2*inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            # FIX FOR LINE 1522: Corrected syntax here
            infra_data = [
                [Paragraph("Registrar", label_style), Paragraph(whois.get("registrar", "Unknown"), body_style)],
                [Paragraph("Primary Owner", label_style), Paragraph(manual.get("primaryOwner", "Not Set"), body_style)],
                [Paragraph("Department", label_style), Paragraph(manual.get("department", "Not Set"), body_style)],
                [Paragraph("Purpose", label_style), Paragraph(manual.get("purpose", "Unknown"), body_style)],
                [Paragraph("Hosting Provider", label_style), Paragraph(manual.get("hostingProvider", "Not Set"), body_style)]
            ]
            
            infra_table = Table(infra_data, colWidths=[1.5*inch, 3.5*inch])
            infra_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
            ]))
            card_elements.append(infra_table)
            
            elements.append(KeepTogether(card_elements))
            elements.append(Spacer(1, 20))

    doc.build(elements)
    buffer.seek(0)
    return buffer

# ================= OLD GLOBAL DOMAIN REPORT =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual_data = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
            if exp_date_str:
                try:
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    if (exp_date - datetime.utcnow()).days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual_data,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 2.0*inch, 1.5*inch])
        
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{d.domain_name}</b></font>"
            status_text = f"<font color='white'>{ssl.get('status', 'Unknown')}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[4*inch, 2*inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            infra_data = [
                ["Registrar", whois.get("registrar", "Unknown")],
                ["Primary Owner", manual.get("primaryOwner", manual.get("owner", "Not Set"))],
                ["Department", manual.get("department", "Not Set")],
                ["Purpose", manual.get("purpose", "Unknown")]
            ]
            
            infra_table = Table(infra_data, colWidths=[1.5*inch, 3.5*inch])
            infra_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
            ]))
            card_elements.append(infra_table)
            
            elements.append(KeepTogether(card_elements))
            elements.append(Spacer(1, 20))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/monitoring/global-report")
async def download_global_monitoring_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user)):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        state_data = {
            "targets": list(state.targets),
            "current_statuses": dict(state.current_statuses),
            "histories": {k: list(v) for k, v in state.histories.items()}
        }
        pdf_buffer = generate_global_monitoring_pdf(data.password, state_data)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=cyberguard_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to generate report: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= SINGLE DOMAIN REPORT GENERATION =================

def formatDate(date_str):
    if not date_str: return "N/A"
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%B %d, %Y")
    except:
        return date_str

def generate_single_domain_pdf(domain_id: int, db: Session, password: str):
    """Generates a detailed PDF for a single specific domain."""
    d = db.query(Domain).filter(Domain.id == domain_id).first()
    if not d: raise HTTPException(status_code=404, detail="Domain not found")

    # Robust JSON parsing
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except (json.JSONDecodeError, TypeError):
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72, 
                            encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=32, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=30)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=20, textColor=WHITE, backColor=DARK_BG, spaceBefore=20, spaceAfter=15, 
                                  borderPadding=12, alignment=TA_CENTER, borderWidth=1, borderColor=CYBER_CYAN, borderRadius=6)
    section_title_style = ParagraphStyle('SectionTitle', parent=styles['Heading3'], fontSize=16, textColor=PDF_TITLE_COLOR, spaceBefore=25, spaceAfter=12, leading=20)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')

    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"<b>Domain Intelligence Report</b>", subtitle_style))
    
    status_color = STATUS_GREEN if ssl_data.get("status") == "Valid" else STATUS_RED
    status_txt = ssl_data.get("status", "Unknown").upper()
    
    exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
    risk_txt = "Low"
    if exp_date_str:
        try:
            exp_dt = datetime.strptime(exp_date_str.split('T')[0], "%Y-%m-%d")
            days = (exp_dt - datetime.utcnow()).days
            if days < 0: risk_txt = "Expired"
            elif days < 30: risk_txt = "Critical"
        except: pass

    domain_header_data = [
        [Paragraph(f"<b>{d.domain_name}</b>", ParagraphStyle('DH', fontSize=18, textColor=WHITE)), 
         Paragraph(f"<b>{status_txt}</b>", ParagraphStyle('DHS', fontSize=14, textColor=WHITE, alignment=TA_RIGHT))]
    ]
    dh_table = Table(domain_header_data, colWidths=[4*inch, 2*inch])
    dh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(dh_table)
    elements.append(Spacer(1, 20))

    vital_data = [
        [Paragraph("Registrar", label_style), Paragraph(whois_data.get("registrar", "Unknown"), body_style)],
        [Paragraph("Risk Level", label_style), Paragraph(f"<font color='{status_color.hexval() if hasattr(status_color, 'hexval') else '#000'}'><b>{risk_txt}</b></font>", body_style)],
        [Paragraph("Expiration", label_style), Paragraph(formatDate(exp_date_str) if exp_date_str else "Unknown", body_style)],
        [Paragraph("SSL Issuer", label_style), Paragraph(ssl_data.get("issuer", "Unknown"), body_style)]
    ]
    vital_table = Table(vital_data, colWidths=[1.8*inch, 4*inch])
    vital_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,1), 10),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(vital_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Ownership & Infrastructure", section_title_style))
    owner_data = [
        [Paragraph("Primary Owner", label_style), Paragraph(manual_data.get("primaryOwner", "Not Set"), body_style)],
        [Paragraph("Department", label_style), Paragraph(manual_data.get("department", "Not Set"), body_style)],
        [Paragraph("Purpose", label_style), Paragraph(manual_data.get("purpose", "Unknown").upper(), body_style)],
        [Paragraph("DNS Provider", label_style), Paragraph(manual_data.get("dnsProvider", "Not Set"), body_style)],
        [Paragraph("Hosting Provider", label_style), Paragraph(manual_data.get("hostingProvider", "Not Set"), body_style)]
    ]
    owner_table = Table(owner_data, colWidths=[1.8*inch, 4*inch])
    owner_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(owner_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Security Compliance", section_title_style))
    sec_checklist = manual_data.get("security", {})
    sec_data = [
        [Paragraph("Registrar Lock", label_style), Paragraph("Active" if sec_checklist.get('lock') else "Inactive", body_style)],
        [Paragraph("MFA Enabled", label_style), Paragraph("Yes" if sec_checklist.get('mfa') else "No", body_style)],
        [Paragraph("DNSSEC Enabled", label_style), Paragraph("Yes" if sec_checklist.get('dnssec') else "No", body_style)],
    ]
    sec_table = Table(sec_data, colWidths=[1.8*inch, 4*inch])
    sec_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(sec_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("DNS Infrastructure", section_title_style))
    if dns_data:
        for r_type, records in dns_data.items():
            if records:
                elements.append(Paragraph(f"<b>{r_type} Records ({len(records)})</b>", ParagraphStyle('DNSHead', fontSize=12, textColor=CYBER_CYAN, spaceAfter=6)))
                for rec in records:
                    elements.append(Paragraph(f"• {rec}", body_style))
                elements.append(Spacer(1, 10))
    else:
        elements.append(Paragraph("No DNS records found.", body_style))
    
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("Audit Log", section_title_style))
    notes = manual_data.get("notes", [])
    if notes:
        for note in notes:
            date = note.get('date', '')[:10]
            txt = note.get('text', '')
            elements.append(Paragraph(f"<b>{date}:</b> {txt}", body_style))
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph("No audit logs available.", body_style))

    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by CyberGuard AI", ParagraphStyle('Footer', fontSize=9, textColor=GRAY_TEXT, alignment=TA_CENTER)))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/report/{id}")
async def download_single_domain_report(
    id: int, 
    data: GlobalReportRequest, 
    current_user: User = Depends(auth.get_current_user), 
    db: Session = Depends(get_db)
):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        pdf_buffer = generate_single_domain_pdf(id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Single Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= OLD GLOBAL DOMAIN REPORT =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual_data = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
            if exp_date_str:
                try:
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    if (exp_date - datetime.utcnow()).days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual_data,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 2.0*inch, 1.5*inch])
        
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{d.domain_name}</b></font>"
            status_text = f"<font color='white'>{ssl.get('status', 'Unknown')}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[4*inch, 2*inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            infra_data = [
                ["Registrar", whois.get("registrar", "Unknown")],
                ["Primary Owner", manual.get("primaryOwner", manual.get("owner", "Not Set"))],
                ["Department", manual.get("department", "Not Set")],
                ["Purpose", manual.get("purpose", "Unknown").upper()],
            ]
            
            t_infra = Table(infra_data, colWidths=[1.5*inch, 4.5*inch])
            
            t_infra.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 0), (0, -1), PDF_MUTED_COLOR),
                ('TEXTCOLOR', (1, 0), (1, -1), PDF_TEXT_COLOR),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5)
            ]))
            card_elements.append(t_infra)
            card_elements.append(Spacer(1, 15))

            exp_str = whois.get("expires") or manual.get("expirationDate") or "N/A"
            if "T" in exp_str: exp_str = exp_str.split("T")[0]
            
            risk_color = STATUS_GREEN
            risk_txt = "Good"
            try:
                if exp_str != "N/A":
                    exp_dt = datetime.strptime(exp_str, "%Y-%m-%d")
                    days = (exp_dt - datetime.utcnow()).days
                    if days < 0: risk_color, risk_txt = STATUS_RED, "Expired"
                    elif days < 30: risk_color, risk_txt = STATUS_ORANGE, "Critical"
            except: pass

            risk_box = Paragraph(
                f"<b>Expiration Risk:</b> <font color='{risk_color.hexval() if hasattr(risk_color, 'hexval') else '#000'}'>{risk_txt} ({exp_str})</font>", 
                ParagraphStyle('Risk', fontSize=10, backColor=colors.HexColor("#f3f4f6"), padding=5, border=1, borderColor=colors.HexColor("#e5e7eb"))
            )
            card_elements.append(risk_box)
            card_elements.append(Spacer(1, 15))

            if dns:
                dns_text = "<b>DNS Records:</b> "
                for r_type, records in dns.items():
                    if records:
                        count = len(records)
                        dns_text += f"{r_type}({count}) "
                card_elements.append(Paragraph(dns_text, ParagraphStyle('DNS', fontSize=9, textColor=PDF_MUTED_COLOR)))
                card_elements.append(Spacer(1, 5))

            notes = manual.get("notes", [])
            if notes and len(notes) > 0:
                card_elements.append(Paragraph("<b>Audit Log / Notes:</b>", ParagraphStyle('NoteHead', fontSize=10, textColor=PDF_TITLE_COLOR)))
                for note in notes[:3]: 
                    date = note.get('date', '')[:10]
                    txt = note.get('text', '')
                    card_elements.append(Paragraph(f"• <i>{date}:</i> {txt}", ParagraphStyle('NoteBody', fontSize=8, textColor=PDF_TEXT_COLOR, leftIndent=10)))
                card_elements.append(Spacer(1, 10))

            line = Table([['']], colWidths=[6.5*inch])
            line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 1, colors.HexColor("#e5e7eb"))]))
            card_elements.append(line)
            card_elements.append(Spacer(1, 20))

            elements.append(KeepTogether(card_elements))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/global-report")
async def download_global_domain_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    try:
        pdf_buffer = generate_global_domain_report(current_user.id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_intel_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= HYBRID SUBDOMAIN DISCOVERY =================
SAFE_SUBDOMAIN_LIST = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'imap', 'admin', 'api', 'dev', 'staging', 'test', 'beta', 'portal', 'shop', 'secure', 'vpn', 'remote', 'blog', 'forum', 'cdn', 'static', 'media', 'assets', 'img', 'images', 'video', 'app', 'apps', 'mobile', 'm', 'store', 'support', 'help', 'wiki', 'docs', 'status', 'panel', 'cpanel', 'webdisk', 'autodiscover', 'autoconfig', 'owa', 'exchange', 'email', 'relay', 'mx', 'mx1', 'mx2', 'news', 'tv', 'radio', 'chat', 'sip', 'proxy', 'gateway', 'monitor', 'jenkins', 'git', 'gitlab', 'svn']

def get_passive_subdomains_sync(domain: str):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    names_raw = entry.get('name_value', '')
                    names_list = names_raw.split('\n')
                    for name in names_list:
                        name = name.strip()
                        if not name: continue
                        if name.startswith('*.'): continue
                        if name.endswith(domain): subdomains.add(name)
            except Exception: pass
    except Exception: pass
    return list(subdomains)

# ================= WEBSITE MONITORING ROUTES =================
@app.post("/start")
async def start_monitoring(request: StartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    if state.is_monitoring: raise HTTPException(status_code=400, detail="Already monitoring")
    parsed = urlparse(request.url)
    domain = parsed.netloc
    scheme = parsed.scheme
    loop = asyncio.get_event_loop()
    passive_subs = await loop.run_in_executor(None, get_passive_subdomains_sync, domain)
    active_subs = []
    for sub in SAFE_SUBDOMAIN_LIST:
        full_domain = f"{sub}.{domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, full_domain)
            active_subs.append(f"{scheme}://{full_domain}")
        except socket.gaierror: pass
    sub_urls = set()
    sub_urls.add(request.url)
    for sub in passive_subs: sub_urls.add(f"{scheme}://{sub}")
    sub_urls.update(active_subs)
    state.targets = list(sub_urls)
    state.is_monitoring = True
    state.target_url = request.url
    state.detectors = {t: SmartDetector(alpha=0.15, threshold=2.0) for t in state.targets}
    state.histories = {}; state.timestamps = {}; state.baseline_avgs = {}
    state.current_statuses = {t: "Idle" for t in state.targets}
    existing_monitor = db.query(Monitor).filter(Monitor.user_id == current_user.id, Monitor.target_url == request.url).first()
    if existing_monitor: existing_monitor.is_active = True
    else:
        new_monitor = Monitor(user_id=current_user.id, target_url=request.url, friendly_name=request.url, is_active=True)
        db.add(new_monitor)
    db.commit()
    background_tasks.add_task(monitoring_loop, state)
    return {"message": f"Monitoring Started", "targets": state.targets}

@app.post("/stop")
async def stop_monitoring(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    state.is_monitoring = False
    for t in state.targets: state.current_statuses[t] = "Stopped"
    db_monitor = db.query(Monitor).filter(Monitor.user_id == current_user.id, Monitor.target_url == state.target_url).first()
    if db_monitor:
        db_monitor.is_active = False
        db.commit()
    return {"message": "Stopped"}

@app.get("/status")
async def get_status(current_user: User = Depends(auth.get_current_user)):
    return {
        "is_monitoring": state.is_monitoring,
        "target_url": state.target_url,
        "targets": state.targets,
        "current_latencies": {t: state.histories.get(t, [0])[-1] if t in state.histories else 0 for t in state.targets},
        "baseline_avgs": state.baseline_avgs,
        "status_messages": state.current_statuses,
        "histories": state.histories,
        "timestamps": state.timestamps
    }
# ================= DOMAIN TRACKING LOGIC =================

# FIX: RDAP function to return dict with errors instead of None
def _get_rdap_info_ultra(domain_name):
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'Accept': 'application/rdap+json', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
        if response.status_code == 200:
            data = response.json()
            info = {"registrar": None, "created": None, "expires": None}
            events = data.get("events", [])
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                if "expir" in action: info["expires"] = date_val
                if "regist" in action or "creat" in action: info["created"] = date_val
            entities = data.get("entities", [])
            for entity in entities:
                roles = [str(r).lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray")
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]; break
                    if not info["registrar"]: info["registrar"] = "Redacted"
            return info, "RDAP"
        else: 
            return {"registrar": "Error", "created": None, "expires": None}, "Error"
    except Exception as e: 
        return {"registrar": f"Error: {str(e)[:20]}", "created": None, "expires": None}, "Error"

def _parse_date_string(date_str):
    if not date_str: return None
    date_formats = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y.%m.%d", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    clean_str = str(date_str).split('T')[0].split('+')[0].split('Z')[0]
    for fmt in date_formats:
        try: return datetime.strptime(clean_str, fmt)
        except ValueError: continue
    return None

async def _send_expiry_alert(email: str, domain_name: str, expiry_date: str, days_left: int):
    try:
        subject = f"⚠️ URGENT: {domain_name} Expiring in {days_left} Days"
        body = f"<html><body><h2>Domain Expiration Alert</h2><p>{domain_name} expires soon.</p></body></html>"
        conf = auth.conf
        message = MessageSchema(subject=subject, recipients=[email], body=body, subtype="html")
        fm = FastMail(conf)
        await fm.send_message(message)
    except Exception: pass

# FIXED: Robust SSL using Explicit Handshake and PROTOCOL_TLS_CLIENT
# ================= MAIN.PY SSL FIX =================

def _get_cert_via_ssl_module(domain_name):
    """
    Fetches SSL certificate by forcing a specific handshake.
    This is more reliable for self-signed or older servers.
    """
    
    def _fetch_cert(target_ip_or_domain):
        try:
            import socket
            import ssl
            # Clean domain (remove http:// etc)
            target = target_ip_or_domain.replace("https://", "").replace("http://", "").split("/")[0]
            
            # Create a modern SSL Context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create a standard IPv4 Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            
            # 1. Connect to the server on port 443
            sock.connect((target, 443))
            
            # 2. Wrap the socket with SSL
            ssock = context.wrap_socket(sock, server_hostname=target)
            
            # 3. FORCE the handshake to complete
            ssock.do_handshake()
            
            # 4. Get the certificate
            cert = ssock.getpeercert()
            
            # Close connection
            ssock.close()
            
            if not cert:
                return {"status": "No Cert Data", "issuer": "Unknown", "expires": "Unknown"}

            # Extract Issuer
            issuer = "Unknown"
            try:
                for item in cert.get('issuer', []):
                    for sub_item in item:
                        if sub_item[0] == 'organizationName':
                            issuer = sub_item[1]
                            break
                    if issuer != "Unknown": break
            except:
                pass 

            if issuer == "Unknown":
                try:
                    for item in cert.get('issuer', []):
                        for sub_item in item:
                            if sub_item[0] == 'commonName':
                                issuer = sub_item[1]
                                break
                        if issuer != "Unknown": break
                except:
                    pass

            not_after = cert.get('notAfter')
            
            # Determine Validity
            status = "Unknown"
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expiry_date < datetime.utcnow():
                        status = "Expired"
                    else:
                        status = "Valid"
                except ValueError:
                    try:
                        expiry_date = datetime.strptime(not_after.split('T')[0], "%Y-%m-%d")
                        if expiry_date < datetime.utcnow():
                            status = "Expired"
                        else:
                            status = "Valid"
                    except:
                        status = "Invalid Date"
            else:
                status = "No Expiry"

            return {
                "status": status,
                "issuer": issuer,
                "expires": not_after
            }
            
        except socket.timeout:
            return {"status": "Timeout", "issuer": "Unknown", "expires": "Unknown"}
        except ConnectionRefusedError:
            return {"status": "Port 443 Closed", "issuer": "Unknown", "expires": "Unknown"}
        except ssl.SSLError as e:
            return {"status": f"SSL Fail: {str(e)[:20]}", "issuer": "Unknown", "expires": "Unknown"}
        except Exception as e:
            return {"status": "Error", "issuer": "Unknown", "expires": "Unknown"}

    return _fetch_cert(domain_name)
               
# ================= DNS HELPER =================
def get_dns_records(domain):
    """Resolves DNS records for a domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            results[rtype] = []
            
    return results

def run_domain_scan_logic(domain_name):
    """Runs the blocking scan operations."""
    print(f"[SCAN START] Scanning {domain_name}...")
    
    # 1. Get DNS
    dns_data = get_dns_records(domain_name)
    
    # 2. Get SSL (Using the fixed function from previous step)
    ssl_data = _get_cert_via_ssl_module(domain_name)
    
    # 3. Get WHOIS (Using the RDAP function)
    whois_data, _ = _get_rdap_info_ultra(domain_name)
    
    # 4. Prepare Database Payloads
    return {
        "dns": json.dumps(dns_data),
        "ssl": json.dumps(ssl_data),
        "whois": json.dumps(whois_data)
    }

# ================= DOMAIN API ROUTES (MISSING) =================

@app.get("/domain/list")
def list_domains(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns list of domains for the logged-in user."""
    domains = db.query(Domain).filter(Domain.user_id == current_user.id).all()
    
    # Format for frontend
    response = []
    for d in domains:
        response.append({
            "id": d.id,
            "domain_name": d.domain_name,
            "security_score": d.security_score,
            "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
            "ssl_status": json.loads(d.ssl_data).get("status") if d.ssl_data else "Unknown"
        })
    return response

@app.post("/domain/add")
async def add_domain(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(auth.get_current_user)
):
    """Adds a new domain and performs an immediate scan."""
    # Read raw body to get simple string domain
    body = await request.body()
    domain_name = body.decode("utf-8").strip().strip('"\'')
    
    # Basic Validation
    if not domain_name:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    
    # Check duplicates
    existing = db.query(Domain).filter(Domain.domain_name == domain_name, Domain.user_id == current_user.id).first()
    if existing:
        return {"message": "Domain already tracked", "id": existing.id}

    # Create Domain Record (Empty initially)
    new_domain = Domain(
        domain_name=domain_name,
        user_id=current_user.id,
        security_score=0,
        ssl_data="{}",
        whois_data="{}",
        dns_data="{}",
        manual_data="{}"
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    # Run Scan in background to avoid blocking
    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, domain_name)
        
        # Update DB with results
        new_domain.dns_data = scan_results["dns"]
        new_domain.ssl_data = scan_results["ssl"]
        new_domain.whois_data = scan_results["whois"]
        new_domain.last_scanned = datetime.utcnow()
        
        # Calculate a rough score based on status
        ssl_info = json.loads(scan_results["ssl"])
        new_domain.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        # Don't fail the add, just leave data empty if scan fails
        
    return {"message": "Domain added and scanned", "id": new_domain.id}

@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns detailed info for a specific domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Parse JSON data
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except:
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    return {
        "id": d.id,
        "domain_name": d.domain_name,
        "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
        "ssl_status": ssl_data.get("status"),
        "ssl_issuer": ssl_data.get("issuer"),
        "ssl_expires": ssl_data.get("expires"),
        "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"),
        "registrar": whois_data.get("registrar"),
        "dns_records": dns_data,
        "manual_data": manual_data
    }

@app.post("/domain/scan/{id}")
async def rescan_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Forces a rescan of a domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, d.domain_name)
        
        d.dns_data = scan_results["dns"]
        d.ssl_data = scan_results["ssl"]
        d.whois_data = scan_results["whois"]
        d.last_scanned = datetime.utcnow()
        
        # Update score
        ssl_info = json.loads(scan_results["ssl"])
        d.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
        return {"message": "Scan successful"}
    except Exception as e:
        print(f"[RESCAN ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/domain/update-manual/{id}")
def update_manual_domain_data(id: int, data: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Updates manual asset data."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Merge new data with existing manual data
    try:
        existing_manual = json.loads(d.manual_data) if d.manual_data else {}
    except:
        existing_manual = {}
        
    updated_manual = {**existing_manual, **data}
    d.manual_data = json.dumps(updated_manual)
    d.last_scanned = datetime.utcnow() # Update scan time to show 'fresh' data
    
    db.commit()
    return {"message": "Manual data updated"}

@app.delete("/domain/{id}")
def delete_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    db.delete(d)
    db.commit()
    return {"message": "Deleted"}