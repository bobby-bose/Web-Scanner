#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final Unified Web-ScannerFlask Application
Single Flask application with Web-Scanner modules integrated directly
No wrapper, no WebSocket - everything embedded within Flask functions
"""

import os
import sys
import json
import logging
import threading
import hashlib
import time
from datetime import datetime
from typing import Any, Dict, List
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect
from werkzeug.utils import secure_filename

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import dns.resolver
from bs4 import BeautifulSoup

import subprocess
import shlex
from pathlib import Path
import platform

# Add web-scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import database
from database import init_database, reload_wordlists, save_scan_to_database, get_scan_history, get_scan_results_from_db, get_wordlists, delete_scan_from_db

# Setup logging
def setup_logging():
    """Setup comprehensive logging for the application"""
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f'Web-Scanner_web_{datetime.now().strftime("%Y%m%d")}.log')
    
    # Create logger
    app_logger = logging.getLogger('Web-Scanner_web')
    app_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    app_logger.handlers.clear()
    
    # File handler with detailed formatting
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    app_logger.addHandler(file_handler)
    
    # Console handler for important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(levelname)s - %(funcName)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    app_logger.addHandler(console_handler)
    
    return app_logger

# Initialize logger
logger = setup_logging()
logger.info("Starting Web-ScannerWeb Interface - Direct Scan Mode")

# Flask app
app = Flask(__name__)
app.secret_key = 'Web-Scanner_final_app_secret_key_2025'

# MongoDB configuration
MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb+srv://admin:admin@cluster0.t5mooil.mongodb.net/dirsearch?appName=Cluster0')
app.config['MONGODB_URL'] = MONGODB_URL

# Database connection status
db_connection_status = {
    'connected': False,
    'error': None,
    'url': MONGODB_URL
}

try:
    init_database(app)
    db_connection_status['connected'] = True
    logger.info("Database initialized successfully")
except Exception as e:
    db_connection_status['connected'] = False
    db_connection_status['error'] = str(e)
    logger.error(f"Database initialization failed: {e}", exc_info=True)

# Global scan storage
active_scans: Dict[str, Any] = {}
scan_history: List[Dict[str, Any]] = []
scan_results: Dict[str, List[Dict[str, Any]]] = {}

# Global state for active recon runs
active_recons: Dict[str, Any] = {}

# Global state for recon preparation
recon_preparing = False
recon_ready = False
recon_prepare_logs: List[Dict[str, Any]] = []
RECON_READY_FILE = os.path.join(RECON_OUTPUTS_WIN, ".recon_ready")

# reconFTW runner settings
RECONFTW_FOLDER_WIN = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'reconftw'))
RECON_OUTPUTS_WIN = os.path.normpath(os.path.join(os.path.dirname(__file__), 'recon_outputs'))

# Initialize recon_ready from file flag
def _load_recon_ready_state():
    global recon_ready
    recon_ready = os.path.isfile(RECON_READY_FILE)

_load_recon_ready_state()

class DirectScanner:
    """Direct scanner - no initialization, imports modules on demand"""
    
    def __init__(self, scan_id: str, config: Dict[str, Any]):
        self.scan_id = scan_id
        self.config = config
        self.status = "starting"
        self.progress = 0
        self.results = []
        self.start_time = datetime.now()
        self.end_time = None
        self.error = None
        self.debug_info = []
        self.should_stop = False
        
    def log_debug(self, message: str, level: str = "INFO"):
        """Add debug message for UI display"""
        debug_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        self.debug_info.append(debug_entry)
        logger.info(f"Scanner {self.scan_id}: {message}")
        
    def import_on_demand(self, module_name: str, import_path: str):
        """Import module only when needed"""
        try:
            self.log_debug(f"Importing {module_name}...")
            module = __import__(import_path, fromlist=[module_name])
            self.log_debug(f"Successfully imported {module_name}")
            return module
        except Exception as e:
            error_msg = f"Failed to import {module_name}: {str(e)}"
            self.log_debug(error_msg, "ERROR")
            self.error = error_msg
            self.status = "error"
            raise
            
    def execute_scan_function(self):
        """Execute scan directly without initialization"""
        try:
            self.status = "scanning"
            self.log_debug("Starting direct scan execution")
            
            # Import modules on demand
            self.log_debug("Step 1: Importing required modules")
            
            # Import basic data structures
            from web_scanner.lib.core.data import options, blacklists
            self.log_debug("Imported options and blacklists")
            
            # Import settings
            from web_scanner.lib.core.settings import SCRIPT_PATH
            self.log_debug("Imported settings")
            
            # Setup minimal options
            selected_wordlist = self.config.get("wordlist", "db/dicc.txt")
            if isinstance(selected_wordlist, str):
                selected_wordlist = selected_wordlist.replace("\\", "/")

            options.clear()
            options.update({
                "urls": [self.config["url"]],
                "http_method": self.config.get("http_method", "GET").upper(),
                "extensions": tuple(self.config.get("extensions", "php,html").split(",")),
                "wordlists": selected_wordlist,
                "thread_count": int(self.config.get("threads", 5)),
                "timeout": int(self.config.get("timeout", 10)),
                "delay": float(self.config.get("delay", 0)),
                "max_retries": int(self.config.get("max_retries", 1)),
                "subdirs": ["/"],
                "max_time": 0,
                "quiet": True,
                "disable_cli": True,
            })
            
            self.progress = 10
            self.log_debug("Basic options configured")
            
            # Import and setup dictionary
            self.log_debug("Step 2: Setting up dictionary")
            from web_scanner.lib.core.dictionary import Dictionary
            from web_scanner.lib.utils.file import FileUtils
            
            wordlist_path = os.path.join(SCRIPT_PATH, options["wordlists"])
            if not os.path.exists(wordlist_path):
                raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
                
            self.dictionary = Dictionary(files=[wordlist_path])
            self.progress = 30
            self.log_debug(f"Dictionary loaded with {len(self.dictionary)} entries")
            
            # Import and setup requester
            self.log_debug("Step 3: Setting up requester")
            from web_scanner.lib.connection.requester import Requester
            
            self.requester = Requester()
            self.requester.set_url(self.config["url"])
            self.progress = 50
            self.log_debug(f"Requester setup for {self.config['url']}")
            
            # Start actual scanning
            self.log_debug("Step 5: Starting actual path scanning")
            scanned_count = 0
            all_paths = list(self.dictionary)
            total_paths = len(all_paths)
            if total_paths <= 0:
                self.log_debug("Dictionary is empty; nothing to scan", "WARNING")
                total_paths = 0

            for path in all_paths:
                if self.should_stop:
                    self.log_debug("Scan stopped by user")
                    break
                    
                try:
                    # Make request directly
                    response = self.requester.request('/' + path.lstrip('/'))
                    
                    # Check if path found (status 200-299 or 3xx)
                    if 200 <= response.status < 400:
                        result = {
                            "path": path,
                            "status": response.status,
                            "size": len(response.content) if response.content else 0,
                            "url": self.config["url"].rstrip('/') + '/' + path.lstrip('/'),
                            "timestamp": datetime.now().isoformat()
                        }
                        self.results.append(result)
                        self.log_debug(f"FOUND: {path} - {response.status}")
                    
                    scanned_count += 1
                    if total_paths > 0:
                        # 50%..100% while scanning
                        self.progress = 50 + (scanned_count / total_paths) * 50
                    if scanned_count % 10 == 0:
                        self.log_debug(f"Scanned {scanned_count}/{total_paths} paths")
                        
                except Exception as e:
                    self.log_debug(f"Error scanning {path}: {str(e)}", "WARNING")
                    continue
            
            self.progress = 100
            self.status = "completed"
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            self.log_debug(f"Scan completed - Found {len(self.results)} paths in {duration:.2f}s")
            
            # Save to database
            try:
                save_scan_to_database(self)
            except Exception as e:
                self.log_debug(f"Failed to save scan to database: {str(e)}", "ERROR")

        except Exception as e:
            self.error = str(e)
            self.status = "error"
            self.log_debug(f"Scan failed: {str(e)}", "ERROR")
            self.log_debug(f"Full error: {repr(e)}", "ERROR")
            import traceback
            self.log_debug(f"Traceback: {traceback.format_exc()}", "ERROR")
            
    def stop_scan_function(self):
        """Stop the scan"""
        self.should_stop = True
        self.status = "stopped"
        self.log_debug("Scan stop requested")


class ReconRunner:
    """Python-only reconnaissance runner"""

    def __init__(self, recon_id: str, config: Dict[str, Any]):
        self.recon_id = recon_id
        self.scan_id = recon_id  # for DB compatibility
        self.config = config
        self.status = "starting"
        self.progress = 0
        self.results: Dict[str, Any] = {
            "domain": config.get("domain"),
            "subdomains": [],
            "dns_records": {},
            "live_hosts": [],
            "summary": {},
        }
        self.start_time = datetime.now()
        self.end_time = None
        self.error = None
        self.debug_info: List[Dict[str, Any]] = []
        self.should_stop = False

        # DB compatibility fields
        self.results_count = 0

    def log_debug(self, message: str, level: str = "INFO"):
        debug_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
        }
        self.debug_info.append(debug_entry)
        if level == "ERROR":
            logger.error(f"Recon {self.recon_id}: {message}")
        elif level == "WARNING":
            logger.warning(f"Recon {self.recon_id}: {message}")
        else:
            logger.info(f"Recon {self.recon_id}: {message}")

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        domain = (domain or "").strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0]
        return domain

    def _crtsh_subdomains(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        self.log_debug(f"Querying certificate transparency: {url}")

        try:
            resp = requests.get(url, timeout=25, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                self.log_debug(f"crt.sh returned HTTP {resp.status_code}", "WARNING")
                return []

            try:
                data = resp.json()
            except Exception:
                self.log_debug("crt.sh response is not valid JSON", "WARNING")
                return []

            subs: set[str] = set()
            for row in data:
                nv = (row.get("name_value") or "").strip()
                if not nv:
                    continue

                for item in nv.split("\n"):
                    item = item.strip().lower()
                    item = item.lstrip("*.")
                    if item and item.endswith(domain):
                        subs.add(item)

            return sorted(subs)
        except Exception as e:
            self.log_debug(f"crt.sh query failed: {e}", "WARNING")
            return []

    def _dns_records(self, domain: str) -> Dict[str, Any]:
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        out: Dict[str, Any] = {}
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6

        for rtype in record_types:
            if self.should_stop:
                break
            try:
                answers = resolver.resolve(domain, rtype)
                out[rtype] = [str(a) for a in answers]
            except Exception:
                out[rtype] = []

        return out

    def _probe_one(self, host: str) -> List[Dict[str, Any]]:
        results = []
        for scheme in ("https", "http"):
            if self.should_stop:
                break
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(
                    url,
                    timeout=12,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                title = None
                try:
                    soup = BeautifulSoup(resp.text or "", "html.parser")
                    if soup.title and soup.title.string:
                        title = soup.title.string.strip()[:200]
                except Exception:
                    title = None

                results.append(
                    {
                        "host": host,
                        "url": resp.url or url,
                        "scheme": scheme,
                        "status": resp.status_code,
                        "title": title,
                        "server": resp.headers.get("Server"),
                        "content_length": resp.headers.get("Content-Length"),
                        "timestamp": datetime.now().isoformat(),
                    }
                )
            except Exception:
                continue

        return results

    def execute_recon_function(self):
        try:
            self.status = "running"
            domain_raw = self.config.get("domain")
            domain = self._normalize_domain(domain_raw)
            if not domain:
                raise ValueError("Domain is required")

            self.config["domain"] = domain
            self.config.setdefault("scan_type", "recon")
            self.config.setdefault("mode", "passive")

            self.log_debug(f"Starting recon for domain: {domain}")
            self.progress = 5

            if self.should_stop:
                self.status = "stopped"
                self.end_time = datetime.now()
                return

            # Step 1: Subdomain enumeration (CT)
            self.log_debug("Step 1/3: Discovering subdomains (certificate transparency)")
            subdomains = self._crtsh_subdomains(domain)
            if domain not in subdomains:
                subdomains = [domain] + subdomains
            self.results["subdomains"] = subdomains
            self.progress = 35
            self.log_debug(f"Discovered {len(subdomains)} unique subdomains")

            if self.should_stop:
                self.status = "stopped"
                self.end_time = datetime.now()
                return

            # Step 2: DNS records
            self.log_debug("Step 2/3: Collecting DNS records")
            self.results["dns_records"] = {
                "root": self._dns_records(domain)
            }
            self.progress = 55

            if self.should_stop:
                self.status = "stopped"
                self.end_time = datetime.now()
                return

            # Step 3: HTTP probing
            self.log_debug("Step 3/3: Probing hosts (HTTP/HTTPS)")
            max_hosts = int(self.config.get("max_hosts", 200))
            targets = subdomains[:max_hosts]
            live_hosts: List[Dict[str, Any]] = []
            workers = int(self.config.get("threads", 20))

            completed = 0
            total = max(len(targets), 1)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {executor.submit(self._probe_one, host): host for host in targets}
                for future in as_completed(future_map):
                    if self.should_stop:
                        break
                    host = future_map[future]
                    try:
                        res = future.result() or []
                        live_hosts.extend(res)
                    except Exception as e:
                        self.log_debug(f"Probe error for {host}: {e}", "WARNING")

                    completed += 1
                    self.progress = 55 + (completed / total) * 40
                    if completed % 10 == 0:
                        self.log_debug(f"Probed {completed}/{total} hosts")

            self.results["live_hosts"] = live_hosts
            self.results["summary"] = {
                "subdomains": len(self.results.get("subdomains") or []),
                "live_endpoints": len(live_hosts),
            }
            self.results_count = len(live_hosts)

            self.progress = 100
            self.status = "completed" if not self.should_stop else "stopped"
            self.end_time = datetime.now()

            # Save to DB
            try:
                self.url = f"https://{domain}"  # used by DB collection naming
                save_scan_to_database(self)
            except Exception as e:
                self.log_debug(f"Failed to save recon to database: {e}", "ERROR")

            duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
            self.log_debug(f"Recon finished with status={self.status} in {duration:.2f}s")

        except Exception as e:
            self.error = str(e)
            self.status = "error"
            self.end_time = datetime.now()
            self.log_debug(f"Recon failed: {self.error}", "ERROR")

    def stop_recon_function(self):
        self.should_stop = True
        self.status = "stopped"
        self.log_debug("Recon stop requested")


def _windows_path_to_wsl(path: str) -> str:
    # If we're already on a Unix-like filesystem path (e.g. Render/Linux),
    # there's no concept of drive letters. reconFTW via WSL is Windows-only,
    # but we defensively avoid crashing on such paths.
    if isinstance(path, str) and path.startswith('/'):
        return path
    p = os.path.abspath(path)
    drive, rest = os.path.splitdrive(p)
    if not drive:
        raise ValueError(f"Path has no drive letter: {path}")
    drive_letter = drive.rstrip(':').lower()
    rest = rest.replace('\\', '/')
    return f"/mnt/{drive_letter}{rest}"


def _safe_domain(domain: str) -> str:
    domain = (domain or '').strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split('/')[0]
    if not re.fullmatch(r"[a-z0-9][a-z0-9\.-]*[a-z0-9]", domain or ""):
        raise ValueError("Invalid domain")
    return domain


class ReconFTWRunner:
    """ReconFTW runner natively on Linux (Render). Downloads/updates reconFTW repo, installs tools, runs reconftw.sh."""

    def __init__(self, recon_id: str, config: Dict[str, Any]):

        self.recon_id = recon_id
        self.scan_id = recon_id  # DB compatibility
        self.config = config
        self.status = "starting"
        self.progress = 0
        self.start_time = datetime.now()
        self.end_time = None
        self.error = None
        self.debug_info: List[Dict[str, Any]] = []
        self.should_stop = False
        self.process: subprocess.Popen | None = None

        # Paths
        self.output_dir_win = os.path.join(RECON_OUTPUTS_WIN, recon_id)
        self.reconftw_dir_target = RECONFTW_FOLDER_WIN

        self.results: Dict[str, Any] = {
            "engine": "reconftw",
            "domain": config.get("domain"),
            "output_dir": self.output_dir_win,
            "artifacts": {},
            "summary": {},
        }
        self.results_count = 0

    def log_debug(self, message: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
        }
        self.debug_info.append(entry)
        if level == "ERROR":
            logger.error(f"ReconFTW {self.recon_id}: {message}")
        elif level == "WARNING":
            logger.warning(f"ReconFTW {self.recon_id}: {message}")
        else:
            logger.info(f"ReconFTW {self.recon_id}: {message}")

    def _run_bash(self, bash_cmd: str, timeout: int | None = None, capture: bool = True):
        """Run a bash command; for long-running scans set capture=False to stream logs."""
        self.log_debug(f"Linux cmd: {bash_cmd}")
        if capture:
            return subprocess.run(["bash", "-lc", bash_cmd], capture_output=True, text=True, timeout=timeout)
        else:
            # For long-running subprocess
            return subprocess.Popen(["bash", "-lc", bash_cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

    def _preflight_and_autoinstall(self):
        """No-op: tools are installed via /api/recon/prepare."""
        self.log_debug("Preflight: skipping (tools should be ready via prepare step)")

    def _read_text_file(self, rel_path: str, limit_lines: int = 5000) -> List[str]:
        p = os.path.join(self.output_dir_win, rel_path)
        if not os.path.isfile(p):
            return []
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= limit_lines:
                        break
                    lines.append(line.rstrip('\n'))
                return lines
        except Exception:
            return []

    def _list_output_files(self, max_files: int = 400) -> List[Dict[str, Any]]:
        out = []
        base = Path(self.output_dir_win)
        if not base.exists():
            return out
        try:
            for p in base.rglob('*'):
                if len(out) >= max_files:
                    break
                if p.is_file():
                    rel = str(p.relative_to(base)).replace('\\', '/')
                    out.append({
                        "path": rel,
                        "size": p.stat().st_size,
                    })
        except Exception:
            return out
        return out

    def _parse_artifacts(self):
        artifacts = {
            "subdomains": self._read_text_file('subdomains/subdomains.txt'),
            "webs_all": self._read_text_file('webs/webs_all.txt'),
            "webs": self._read_text_file('webs/webs.txt'),
            "nuclei_info": self._read_text_file('nuclei_output/info.txt'),
            "nuclei_low": self._read_text_file('nuclei_output/low.txt'),
            "nuclei_medium": self._read_text_file('nuclei_output/medium.txt'),
            "nuclei_high": self._read_text_file('nuclei_output/high.txt'),
            "nuclei_critical": self._read_text_file('nuclei_output/critical.txt'),
        }
        artifacts = {k: v for k, v in artifacts.items() if v}
        self.results["artifacts"] = artifacts
        self.results["output_files"] = self._list_output_files()
        self.results["summary"] = {
            "subdomains": len(artifacts.get('subdomains', [])),
            "webs": len(artifacts.get('webs_all', [])) or len(artifacts.get('webs', [])),
            "nuclei": sum(len(artifacts.get(k, [])) for k in ['nuclei_info','nuclei_low','nuclei_medium','nuclei_high','nuclei_critical']),
        }
        self.results_count = int(self.results["summary"].get("nuclei", 0) or 0)

    def execute_recon_function(self):
        try:
            self.status = "running"
            self.progress = 1

            os.makedirs(self.output_dir_win, exist_ok=True)

            domain = _safe_domain(self.config.get('domain'))
            self.config['domain'] = domain
            self.config.setdefault('scan_type', 'recon')
            self.config.setdefault('engine', 'reconftw')
            self.config.setdefault('auto_install', True)
            self.results['domain'] = domain
            self.url = f"https://{domain}"  # DB collection naming

            # Preflight check + auto-install if needed
            self.log_debug("ReconFTW: starting preflight")
            self.progress = 3
            self._preflight_and_autoinstall()
            self.progress = 8

            if self.should_stop:
                self.status = "stopped"
                self.end_time = datetime.now()
                return

            # Run reconftw natively
            flags = self.config.get('reconftw_flags') or "-r"
            # restrict flags to a safe subset (avoid arbitrary injection)
            if not isinstance(flags, str) or not re.fullmatch(r"[\w\s\-\.]+", flags.strip()):
                flags = "-r"

            # Ensure output directory exists
            os.makedirs(self.output_dir_win, exist_ok=True)

            # Run reconftw.sh
            bash_cmd = (
                f"cd {shlex.quote(self.reconftw_dir_target)} && "
                f"chmod +x reconftw.sh && "
                f"./reconftw.sh -d {shlex.quote(domain)} {flags.strip()} -o {shlex.quote(self.output_dir_win)}/"
            )

            self.log_debug("ReconFTW: launching scan")
            self.progress = 10

            self.process = self._run_bash(bash_cmd, capture=False)

            last_progress = 10
            if self.process.stdout:
                for line in self.process.stdout:
                    if self.should_stop:
                        break
                    line = (line or '').rstrip('\n')
                    if line:
                        self.log_debug(line)

                    # heuristic progress bump
                    if last_progress < 90:
                        last_progress += 0.05
                        self.progress = last_progress

            if self.should_stop and self.process and self.process.poll() is None:
                try:
                    self.process.terminate()
                except Exception:
                    pass

            rc = self.process.wait(timeout=60) if self.process else 1
            if self.should_stop:
                self.status = "stopped"
            elif rc == 0:
                self.status = "completed"
            else:
                self.status = "error"
                self.error = f"reconftw exited with code {rc}"

            self.progress = 95
            self.end_time = datetime.now()

            # Parse key output files into results
            self._parse_artifacts()
            self.progress = 100

            # Save to DB
            try:
                save_scan_to_database(self)
            except Exception as e:
                self.log_debug(f"Failed to save reconFTW run to database: {e}", "ERROR")

        except Exception as e:
            self.error = str(e)
            self.status = "error"
            self.end_time = datetime.now()
            self.log_debug(f"ReconFTW failed: {self.error}", "ERROR")

    def stop_recon_function(self):
        self.should_stop = True
        self.status = "stopped"
        self.log_debug("ReconFTW stop requested")
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

# Flask Routes
@app.route('/')
def index_function():
    """Main dashboard"""
    logger.debug("Dashboard page requested")
    return render_template('index.html')

@app.route('/scan')
def scan_page_function():
    """Scan configuration page"""
    logger.debug("Scan page requested")
    return render_template('scan.html')

@app.route('/history')
def history_page_function():
    """Scan history page"""
    logger.debug("History page requested")
    return render_template('history.html')


@app.route('/recon')
def recon_page_function():
    logger.debug("Recon page requested")
    return render_template('recon.html')


@app.route('/recon/history')
def recon_history_page_function():
    logger.debug("Recon history page requested")
    return render_template('recon_history.html')

@app.route('/config')
def config_page_function():
    """Configuration page"""
    logger.debug("Config page requested")
    return redirect('/')

# API Routes - all embedded functions
@app.route('/api/db/status', methods=['GET'])
def db_status_function():
    """Get database connection status"""
    return jsonify({
        "status": "success",
        "database": db_connection_status
    })

@app.route('/api/scan/start', methods=['POST'])
def start_scan_function():
    """Start scan API"""
    logger.info("Start scan API called")
    try:
        config = request.get_json()
        logger.info(f"Start scan API called with config: {config}")
        
        # Generate scan ID
        scan_id = f"scan_{int(time.time())}_{hash(str(config)) % 10000}"
        
        # Create direct scanner
        scanner = DirectScanner(scan_id, config)
        active_scans[scan_id] = scanner
        
        logger.info(f"Created direct scanner {scan_id}")
        
        # Start scan in background thread
        def scan_thread():
            try:
                with app.app_context():
                    scanner.execute_scan_function()
            except Exception as e:
                logger.error(f"Scan thread error: {str(e)}", exc_info=True)
                scanner.error = str(e)
                scanner.status = "error"
        
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        logger.info(f"Direct scanner {scan_id} thread started")
        
        return jsonify({
            "message": "Direct scan started successfully",
            "scan_id": scan_id,
            "status": "success"
        })
        
    except Exception as e:
        logger.error(f"Failed to start direct scan: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/api/recon/prepare', methods=['POST'])
def prepare_recon():
    global recon_preparing, recon_ready, recon_prepare_logs
    logger.info("Prepare recon API called")
    if recon_preparing:
        return jsonify({
            "status": "running",
            "message": "Preparation already in progress",
            "logs": recon_prepare_logs[-50:]  # last 50 logs
        }), 200
    if recon_ready:
        return jsonify({
            "status": "ready",
            "message": "reconFTW tools are already installed and ready",
            "logs": recon_prepare_logs[-50:]
        }), 200

    recon_preparing = True
    recon_ready = False
    recon_prepare_logs = []
    os.makedirs(RECON_OUTPUTS_WIN, exist_ok=True)

    def prepare_thread():
        global recon_preparing, recon_ready, recon_prepare_logs
        try:
            def log(msg, level="INFO"):
                entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": msg}
                recon_prepare_logs.append(entry)
                logger.info(f"[PREPARE] {msg}")

            log("Starting reconFTW preparation")
            # Ensure reconFTW repo exists
            os.makedirs(RECONFTW_FOLDER_WIN, exist_ok=True)
            if not os.path.exists(os.path.join(RECONFTW_FOLDER_WIN, "reconftw.sh")):
                log("Cloning reconFTW repo")
                clone_cmd = f"cd {shlex.quote(os.path.dirname(RECONFTW_FOLDER_WIN))} && git clone https://github.com/six2dez/reconftw.git {shlex.quote(os.path.basename(RECONFTW_FOLDER_WIN))}"
                proc = subprocess.run(["bash", "-lc", clone_cmd], capture_output=True, text=True, timeout=300)
                if proc.returncode != 0:
                    log(f"Failed to clone reconFTW repo: {proc.stderr.strip()[:500]}", "ERROR")
                    raise RuntimeError("Repo clone failed")
            else:
                log("Updating reconFTW repo")
                update_cmd = f"cd {shlex.quote(RECONFTW_FOLDER_WIN)} && git pull"
                proc = subprocess.run(["bash", "-lc", update_cmd], capture_output=True, text=True, timeout=120)
                # ignore pull errors

            log("Running reconFTW install (may take 10-30 minutes)")
            install_cmd = f"cd {shlex.quote(RECONFTW_FOLDER_WIN)} && chmod +x install.sh reconftw.sh && ./install.sh"
            process = subprocess.Popen(["bash", "-lc", install_cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            for line in process.stdout:
                line = (line or "").rstrip()
                if line:
                    log(line)
            process.wait()
            if process.returncode == 0:
                log("reconFTW install completed successfully")
                # Create ready flag file
                with open(RECON_READY_FILE, "w") as f:
                    f.write(datetime.now().isoformat())
                recon_ready = True
                log("Everything is ready!")
            else:
                log(f"Install failed with exit code {process.returncode}", "ERROR")
                raise RuntimeError("Install failed")
        except Exception as e:
            log(f"Preparation failed: {e}", "ERROR")
        finally:
            recon_preparing = False

    threading.Thread(target=prepare_thread, daemon=True).start()
    return jsonify({
        "status": "started",
        "message": "Preparation started",
        "logs": recon_prepare_logs
    }), 202

@app.route('/api/recon/prepare/status', methods=['GET'])
def prepare_status():
    return jsonify({
        "preparing": recon_preparing,
        "ready": recon_ready,
        "logs": recon_prepare_logs[-200:]  # last 200 logs
    })
@app.route('/api/recon/ready-status', methods=['GET'])
def ready_status():
    return jsonify({
        "ready": recon_ready,
        "preparing": recon_preparing
    })

@app.route('/api/recon/start', methods=['POST'])
def start_recon_function():
    logger.info("Start recon API called")
    if not recon_ready:
        return jsonify({
            "status": "error",
            "message": "reconFTW tools are not ready. Click 'Get Ready' first."
        }), 429
    try:
        config = request.get_json() or {}
        logger.info(f"Start recon config: {config}")

        # Normalize domain early so both engines receive consistent values
        if isinstance(config.get('domain'), str):
            try:
                config['domain'] = _safe_domain(config.get('domain'))
            except Exception:
                # Let the runner validate and report in its own error path
                pass

        recon_id = f"recon_{int(time.time())}_{hash(str(config)) % 10000}"
        engine = (config.get('engine') or 'reconftw').strip().lower()
        if engine != 'reconftw':
            return jsonify({
                "status": "error",
                "message": "Only reconFTW engine is supported.",
            }), 400
        runner = ReconFTWRunner(recon_id, config)
        active_recons[recon_id] = runner

        def recon_thread():
            try:
                with app.app_context():
                    runner.execute_recon_function()
            except Exception as e:
                logger.error(f"Recon thread error: {str(e)}", exc_info=True)
                runner.error = str(e)
                runner.status = "error"

        thread = threading.Thread(target=recon_thread)
        thread.daemon = True
        thread.start()

        return jsonify({
            "message": "Recon started successfully",
            "recon_id": recon_id,
            "status": "success",
        })

    except Exception as e:
        logger.error(f"Failed to start recon: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route('/api/recon/file/<recon_id>', methods=['GET'])
def get_recon_file_function(recon_id):
    """Download a file from a reconFTW run output folder (safe, restricted)."""
    try:
        rel = request.args.get('path', '')
        rel = (rel or '').replace('\\', '/').lstrip('/')
        if not rel or '..' in rel:
            return jsonify({"status": "error", "message": "Invalid path"}), 400

        # Determine output directory
        output_dir = None
        if recon_id in active_recons:
            runner = active_recons[recon_id]
            output_dir = runner.results.get('output_dir')
        if not output_dir:
            db_results = get_scan_results_from_db(recon_id)
            if db_results:
                output_dir = (db_results.get('results') or {}).get('output_dir')

        if not output_dir:
            return jsonify({"status": "error", "message": "Recon output not found"}), 404

        base = os.path.abspath(output_dir)
        target = os.path.abspath(os.path.join(base, rel))
        if not target.startswith(base):
            return jsonify({"status": "error", "message": "Forbidden"}), 403
        if not os.path.isfile(target):
            return jsonify({"status": "error", "message": "File not found"}), 404

        return send_from_directory(base, rel, as_attachment=True)
    except Exception as e:
        logger.error(f"Error serving recon file: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/recon/status/<recon_id>', methods=['GET'])
def get_recon_status_function(recon_id):
    if recon_id not in active_recons:
        return jsonify({"status": "error", "message": "Recon not found"}), 404

    runner = active_recons[recon_id]
    return jsonify({
        "status": "success",
        "data": {
            "status": runner.status,
            "progress": runner.progress,
            "error": runner.error,
            "start_time": runner.start_time.isoformat() if runner.start_time else None,
            "end_time": runner.end_time.isoformat() if runner.end_time else None,
            "debug_messages": runner.debug_info[-200:],
            "summary": runner.results.get("summary", {}),
            "config": runner.config,
            "engine": runner.config.get('engine', runner.results.get('engine', 'python')),
        },
    })


@app.route('/api/recon/results/<recon_id>', methods=['GET'])
def get_recon_results_function(recon_id):
    try:
        if recon_id in active_recons:
            runner = active_recons[recon_id]
            return jsonify({
                "status": "success",
                "results": runner.results,
            })

        db_results = get_scan_results_from_db(recon_id)
        if db_results and db_results.get('scan', {}).get('config', {}).get('scan_type') == 'recon':
            return jsonify({
                "status": "success",
                "results": db_results.get('results', {}),
            })

        return jsonify({"status": "error", "message": "Recon not found"}), 404
    except Exception as e:
        logger.error(f"Error getting recon results: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route('/api/recon/stop/<recon_id>', methods=['POST'])
def stop_recon_function(recon_id):
    if recon_id not in active_recons:
        return jsonify({"status": "error", "message": "Recon not found"}), 404

    runner = active_recons[recon_id]
    runner.stop_recon_function()
    return jsonify({
        "status": "success",
        "message": "Recon stop requested",
    })


@app.route('/api/recon/list', methods=['GET'])
def list_recons_function():
    try:
        active_data = []
        for recon_id, runner in active_recons.items():
            engine = runner.config.get('engine', runner.results.get('engine', 'python'))
            summary = runner.results.get('summary', {}) or {}
            if engine == 'reconftw':
                results_count = int(summary.get('nuclei', 0) or summary.get('webs', 0) or 0)
            else:
                results_count = int(summary.get('live_endpoints', 0) or 0)

            active_data.append({
                "id": recon_id,
                "scan_id": recon_id,
                "domain": runner.config.get('domain', 'Unknown'),
                "url": f"https://{runner.config.get('domain', '')}" if runner.config.get('domain') else "",
                "status": runner.status,
                "progress": runner.progress,
                "results_count": results_count,
                "start_time": runner.start_time.isoformat() if runner.start_time else None,
                "end_time": runner.end_time.isoformat() if runner.end_time else None,
                "config": runner.config,
                "engine": engine,
            })

        historical = get_scan_history(limit=200)
        historical_recons = []
        for item in historical:
            try:
                if item.get('config', {}).get('scan_type') != 'recon':
                    continue
                item['domain'] = (item.get('config') or {}).get('domain')
                historical_recons.append(item)
            except Exception:
                continue

        all_recons = active_data + historical_recons
        all_recons.sort(key=lambda x: x.get('start_time', '') or '', reverse=True)
        return jsonify({
            "status": "success",
            "recons": all_recons,
        })
    except Exception as e:
        logger.error(f"Error listing recons: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500

@app.route('/api/scan/debug/<scan_id>', methods=['GET'])
def debug_scan_function(scan_id):
    """Get detailed debug information for scan"""
    if scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    scanner = active_scans[scan_id]
    
    debug_info = {
        "scan_id": scan_id,
        "status": scanner.status,
        "progress": scanner.progress,
        "error": scanner.error,
        "start_time": scanner.start_time.isoformat() if scanner.start_time else None,
        "end_time": scanner.end_time.isoformat() if scanner.end_time else None,
        "results_count": len(scanner.results),
        "debug_messages": scanner.debug_info,
        "config": scanner.config
    }
    
    return jsonify({
        "status": "success",
        "debug": debug_info
    })

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def get_scan_status_function(scan_id):
    """Get scan status API - direct scanner"""
    if scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    scanner = active_scans[scan_id]
    
    response = {
        "status": "success",
        "data": {
            "status": scanner.status,
            "progress": scanner.progress,
            "results_count": len(scanner.results),
            "start_time": scanner.start_time.isoformat() if scanner.start_time else None,
            "end_time": scanner.end_time.isoformat() if scanner.end_time else None,
            "error": scanner.error,
            "config": scanner.config,
            "debug_messages_count": len(scanner.debug_info),
            "jobs_processed": 0,  # For compatibility with UI
            "errors": 0  # For compatibility with UI
        }
    }
    
    return jsonify(response)

@app.route('/api/wordlists', methods=['GET'])
def get_wordlists_function():
    """Get available wordlists from database"""
    try:
        wordlists = get_wordlists()
        return jsonify({
            "status": "success",
            "wordlists": wordlists
        })
    except Exception as e:
        logger.error(f"Error getting wordlists: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/api/wordlists/reload', methods=['GET', 'POST'])
def reload_wordlists_function():
    try:
        result = reload_wordlists()
        if result.get('ok'):
            return jsonify({
                'status': 'success',
                'result': result,
            })

        return jsonify({
            'status': 'error',
            'result': result,
        }), 500
    except Exception as e:
        logger.error(f"Error reloading wordlists: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e),
        }), 500

@app.route('/api/scan/list', methods=['GET'])
def list_scans_function():
    """List all scans API - from database and active scans"""
    try:
        # Get active scans
        active_scans_data = []
        for scan_id, scanner in active_scans.items():
            active_scans_data.append({
                "id": scan_id,
                "scan_id": scan_id,
                "url": scanner.config.get("url", "Unknown"),
                "status": scanner.status,
                "progress": scanner.progress,
                "results_count": len(scanner.results),
                "start_time": scanner.start_time.isoformat() if scanner.start_time else None,
                "end_time": scanner.end_time.isoformat() if scanner.end_time else None,
                "config": scanner.config
            })
        
        # Get historical scans from database
        historical_scans = get_scan_history(limit=100)
        
        # Combine active and historical scans
        all_scans = active_scans_data + historical_scans
        
        return jsonify({
            "status": "success",
            "scans": all_scans
        })
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def get_scan_results_function(scan_id):
    """Get scan results API - check active scans first, then database"""
    try:
        # Check active scans first
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            return jsonify({
                "status": "success",
                "results": scanner.results
            })
        
        # Check database for completed scans
        db_results = get_scan_results_from_db(scan_id)
        if db_results:
            return jsonify({
                "status": "success",
                "results": db_results['results']
            })
        
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/stop/<scan_id>', methods=['POST'])
def stop_scan_function(scan_id):
    """Stop scan API - direct scanner"""
    if scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    scanner = active_scans[scan_id]
    scanner.stop_scan_function()
    
    return jsonify({
        "status": "success",
        "message": "Scan stopped"
    })

@app.route('/api/scan/delete/<scan_id>', methods=['DELETE'])
def delete_scan_function(scan_id):
    """Delete scan API"""
    try:
        # Remove from active scans if present
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        # Delete from database
        success = delete_scan_from_db(scan_id)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Scan deleted successfully"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Scan not found"
            }), 404
            
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Starting Flask development server - Direct Scan Mode")
    try:
        # Initialize database
        init_database(app)
        logger.info("Database initialized successfully")
        
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Flask server failed to start: {str(e)}", exc_info=True)
        raise
