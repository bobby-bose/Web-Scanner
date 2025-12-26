# -*- coding: utf-8 -*-
"""
Database models for Web-ScannerWeb Interface - MongoDB
"""

import os
import re
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from urllib.parse import urlparse

# MongoDB client and database
client = None
db = None

def get_domain_collection_name(url):
    """Generate collection name from URL domain"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        # Clean domain name for MongoDB collection
        domain = re.sub(r'[^a-zA-Z0-9_-]', '_', domain)
        return f"scans_{domain}"
    except Exception:
        return "scans_unknown"

def get_wordlists_collection_name():
    """Get wordlists collection name"""
    return "wordlists"

class ScanManager:
    """MongoDB-based scan manager"""
    
    def __init__(self, database):
        self.db = database
    
    def save_scan(self, scanner):
        """Save scan results to domain-specific collection"""
        try:
            collection_name = get_domain_collection_name(scanner.config.get('url', ''))
            collection = self.db[collection_name]
            
            # Create scan document
            scan_doc = {
                '_id': scanner.scan_id,
                'scan_id': scanner.scan_id,
                'url': scanner.config.get('url', ''),
                'status': scanner.status,
                'progress': scanner.progress,
                'results_count': len(scanner.results),
                'start_time': scanner.start_time,
                'end_time': scanner.end_time,
                'config': scanner.config,
                'error': scanner.error,
                'debug_info': scanner.debug_info,
                'results': scanner.results,
                'created_at': datetime.utcnow()
            }
            
            # Insert or update scan
            collection.replace_one(
                {'_id': scanner.scan_id},
                scan_doc,
                upsert=True
            )
            
            print(f"Successfully saved scan {scanner.scan_id} to collection {collection_name}")
            
        except Exception as e:
            print(f"Error saving scan to MongoDB: {e}")
    
    def get_scan_history(self, limit=50):
        """Get scan history from all domain collections"""
        try:
            all_scans = []
            
            # Get all collection names that start with 'scans_'
            collection_names = self.db.list_collection_names()
            scan_collections = [name for name in collection_names if name.startswith('scans_')]
            
            for collection_name in scan_collections:
                collection = self.db[collection_name]
                scans = list(collection.find({}, {'_id': 1, 'scan_id': 1, 'url': 1, 'status': 1, 
                                                'progress': 1, 'results_count': 1, 'start_time': 1, 
                                                'end_time': 1, 'config': 1, 'error': 1, 'debug_info': 1})
                                 .sort('created_at', -1).limit(limit))
                
                # Convert MongoDB ObjectId to string and format
                for scan in scans:
                    scan['id'] = str(scan.pop('_id'))
                    if scan.get('start_time'):
                        scan['start_time'] = scan['start_time'].isoformat()
                    if scan.get('end_time'):
                        scan['end_time'] = scan['end_time'].isoformat()
                    
                all_scans.extend(scans)
            
            # Sort by start_time and limit
            all_scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)
            return all_scans[:limit]
            
        except Exception as e:
            print(f"Error getting scan history: {e}")
            return []
    
    def delete_scan(self, scan_id):
        """Delete scan from any domain collection"""
        try:
            collection_names = self.db.list_collection_names()
            scan_collections = [name for name in collection_names if name.startswith('scans_')]
            
            for collection_name in scan_collections:
                collection = self.db[collection_name]
                result = collection.delete_one({'_id': scan_id})
                
                if result.deleted_count > 0:
                    print(f"Successfully deleted scan {scan_id} from collection {collection_name}")
                    return True
            
            print(f"Scan {scan_id} not found in any collection")
            return False
            
        except Exception as e:
            print(f"Error deleting scan: {e}")
            return False

def get_scan_results(self, scan_id):
        """Get scan results from any domain collection"""
        try:
            collection_names = self.db.list_collection_names()
            scan_collections = [name for name in collection_names if name.startswith('scans_')]
            
            for collection_name in scan_collections:
                collection = self.db[collection_name]
                scan = collection.find_one({'_id': scan_id})
                
                if scan:
                    # Format scan data
                    scan_data = {
                        'scan': {
                            'id': str(scan.pop('_id')),
                            'scan_id': scan.get('scan_id'),
                            'url': scan.get('url'),
                            'status': scan.get('status'),
                            'progress': scan.get('progress'),
                            'results_count': scan.get('results_count'),
                            'start_time': scan.get('start_time').isoformat() if scan.get('start_time') else None,
                            'end_time': scan.get('end_time').isoformat() if scan.get('end_time') else None,
                            'config': scan.get('config'),
                            'error': scan.get('error'),
                            'debug_info': scan.get('debug_info')
                        },
                        'results': scan.get('results', [])
                    }
                    return scan_data
            
            return None
            
        except Exception as e:
            print(f"Error getting scan results: {e}")
            return None

class WordlistManager:
    """MongoDB-based wordlist manager"""
    
    def __init__(self, database):
        self.db = database
        self.collection = self.db[get_wordlists_collection_name()]
    
    def load_wordlists(self):
        """Load all wordlists from the db folder into MongoDB"""
        project_root = os.path.dirname(os.path.dirname(__file__))

        db_candidates = [
            os.path.join(project_root, 'dirsearch', 'db'),
            os.path.join(project_root, '.research', 'db'),
            os.path.join(project_root, 'research', 'db'),
            os.path.join(project_root, 'db'),
        ]

        db_path = None
        for candidate in db_candidates:
            if os.path.isdir(candidate):
                db_path = candidate
                break

        if db_path is None:
            print(f"Warning: db directory not found. Tried: {db_candidates}")
            return
        
        # Clear existing wordlists
        self.collection.delete_many({})
        
        # Find all .txt files in db folder (recursive)
        for root, _, files in os.walk(db_path):
            for filename in files:
                if not filename.lower().endswith('.txt'):
                    continue

                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, db_path)
                # Store paths relative to Web-Scanner root, using forward slashes for consistency
                stored_path = os.path.join('db', rel_path).replace('\\', '/')
                
                try:
                    # Get file size
                    file_size = os.path.getsize(file_path)
                    
                    # Count entries (lines)
                    entries_count = 0
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            entries_count = sum(1 for _ in f)
                    except Exception:
                        entries_count = None
                    
                    display_name = os.path.splitext(rel_path)[0].replace('\\', '/').replace('_', ' ')

                    # Create wordlist document
                    wordlist_doc = {
                        'name': display_name,
                        'path': stored_path,
                        'size': file_size,
                        'entries_count': entries_count,
                        'description': f"Wordlist from {stored_path}",
                        'created_at': datetime.utcnow(),
                        'last_used': None
                    }
                    
                    self.collection.insert_one(wordlist_doc)
                    print(f"Loaded wordlist: {stored_path} ({entries_count} entries)")
                    
                except Exception as e:
                    print(f"Error loading wordlist {stored_path}: {e}")
        
        # Commit changes (MongoDB handles this automatically)
        try:
            count = self.collection.count_documents({})
            print(f"Successfully loaded {count} wordlists")
        except Exception as e:
            print(f"Error saving wordlists to MongoDB: {e}")
    
    def reload_wordlists(self):
        """Reload wordlists and return result"""
        project_root = os.path.dirname(os.path.dirname(__file__))

        db_candidates = [
            os.path.join(project_root, 'dirsearch', 'db'),
            os.path.join(project_root, '.research', 'db'),
            os.path.join(project_root, 'research', 'db'),
            os.path.join(project_root, 'db'),
        ]

        db_path = None
        for candidate in db_candidates:
            if os.path.isdir(candidate):
                db_path = candidate
                break

        if db_path is None:
            return {
                'ok': False,
                'reason': 'db_directory_not_found',
                'tried': db_candidates,
            }

        files_found = 0
        inserted = 0
        errors = []

        self.collection.delete_many({})

        for root, _, files in os.walk(db_path):
            for filename in files:
                if not filename.lower().endswith('.txt'):
                    continue

                files_found += 1

                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, db_path)
                stored_path = os.path.join('db', rel_path).replace('\\', '/')

                try:
                    file_size = os.path.getsize(file_path)

                    entries_count = 0
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            entries_count = sum(1 for _ in f)
                    except Exception:
                        entries_count = None

                    display_name = os.path.splitext(rel_path)[0].replace('\\', '/').replace('_', ' ')

                    wordlist_doc = {
                        'name': display_name,
                        'path': stored_path,
                        'size': file_size,
                        'entries_count': entries_count,
                        'description': f"Wordlist from {stored_path}",
                        'created_at': datetime.utcnow(),
                        'last_used': None
                    }
                    
                    self.collection.insert_one(wordlist_doc)
                    inserted += 1
                except Exception as e:
                    errors.append({'path': stored_path, 'error': str(e)})

        try:
            count = self.collection.count_documents({})
            return {
                'ok': True,
                'db_path': db_path,
                'files_found': files_found,
                'inserted': inserted,
                'errors': errors,
                'count_in_db': count,
            }
        except Exception as e:
            return {
                'ok': False,
                'reason': 'db_commit_failed',
                'db_path': db_path,
                'files_found': files_found,
                'inserted': inserted,
                'errors': errors,
                'commit_error': str(e),
            }
    
    def get_wordlists(self):
        """Get all wordlists from MongoDB"""
        try:
            wordlists = list(self.collection.find({}).sort('name', 1))
            
            # Convert ObjectId to string and format dates
            for wordlist in wordlists:
                wordlist['id'] = str(wordlist.pop('_id'))
                if wordlist.get('created_at'):
                    wordlist['created_at'] = wordlist['created_at'].isoformat()
                if wordlist.get('last_used'):
                    wordlist['last_used'] = wordlist['last_used'].isoformat()
            
            return wordlists
        except Exception as e:
            print(f"Error getting wordlists: {e}")
            return []

# Global managers
scan_manager = None
wordlist_manager = None

def init_database(app):
    """Initialize MongoDB database connection"""
    global client, db, scan_manager, wordlist_manager
    
    try:
        # Connect to MongoDB
        mongodb_url = app.config.get('MONGODB_URL', 'mongodb://localhost:27017/dirsearch')
        client = MongoClient(mongodb_url)
        
        # Test connection
        client.admin.command('ping')
        
        # Get database name from URL or default
        db_name = mongodb_url.split('/')[-1] if '/' in mongodb_url else 'dirsearch'
        db = client[db_name]
        
        # Initialize managers
        scan_manager = ScanManager(db)
        wordlist_manager = WordlistManager(db)
        
        # Load wordlists
        wordlist_manager.load_wordlists()
        
        print(f"Successfully connected to MongoDB: {mongodb_url}")
        
    except ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}")
        raise
    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise

def get_database():
    """Get database instance"""
    return db

def close_database():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()


# Legacy functions for compatibility
def save_scan_to_database(scanner):
    """Save scan results to database (legacy compatibility)"""
    if scan_manager:
        scan_manager.save_scan(scanner)

def get_scan_history(limit=50):
    """Get scan history from database (legacy compatibility)"""
    if scan_manager:
        return scan_manager.get_scan_history(limit)
    return []

def get_scan_results_from_db(scan_id):
    """Get scan results from database (legacy compatibility)"""
    if scan_manager:
        return scan_manager.get_scan_results(scan_id)
    return None

def delete_scan_from_db(scan_id):
    """Delete scan from database (legacy compatibility)"""
    if scan_manager:
        return scan_manager.delete_scan(scan_id)
    return False

def get_wordlists():
    """Get all wordlists from database (legacy compatibility)"""
    if wordlist_manager:
        return wordlist_manager.get_wordlists()
    return []

def reload_wordlists():
    """Reload wordlists (legacy compatibility)"""
    if wordlist_manager:
        return wordlist_manager.reload_wordlists()
    return {'ok': False, 'reason': 'Database not initialized'}
