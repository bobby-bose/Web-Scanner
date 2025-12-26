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
active_scans: Dict[str, 'DirectScanner'] = {}
scan_history: List[Dict[str, Any]] = []
scan_results: Dict[str, List[Dict[str, Any]]] = {}

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
