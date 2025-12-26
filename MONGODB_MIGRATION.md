# MongoDB Database Migration

## Overview
The database has been successfully migrated from SQLite to MongoDB with a new schema design.

## Key Changes

### 1. Database Configuration
- **Before**: SQLite file (`web_interface/dirsearch.db`)
- **After**: MongoDB connection via environment variable `MONGODB_URL`
- **Default**: `mongodb://localhost:27017/dirsearch`

### 2. Schema Redesign
- **Before**: Fixed tables (`scans`, `scan_results`, `wordlists`)
- **After**: Dynamic collections per domain
  - `scans_{domain}` - One collection per search domain
  - `wordlists` - Single collection for wordlists

### 3. Collection Structure

#### Domain-specific Scan Collections
Each scanned domain gets its own collection:
- `scans_example_com` - Scans for example.com
- `scans_test_org` - Scans for test.org
- etc.

Each document contains:
```json
{
  "_id": "scan_id",
  "scan_id": "scan_id",
  "url": "https://example.com",
  "status": "completed",
  "progress": 100.0,
  "results_count": 15,
  "start_time": "2025-12-26T12:00:00Z",
  "end_time": "2025-12-26T12:05:00Z",
  "config": {...},
  "error": null,
  "debug_info": [...],
  "results": [...],
  "created_at": "2025-12-26T12:00:00Z"
}
```

#### Wordlists Collection
Single `wordlists` collection with documents:
```json
{
  "_id": ObjectId,
  "name": "common passwords",
  "path": "db/dicc.txt",
  "size": 12345,
  "entries_count": 1000,
  "description": "Wordlist from db/dicc.txt",
  "created_at": "2025-12-26T12:00:00Z",
  "last_used": null
}
```

## Usage

### Environment Setup
Set your MongoDB URL:
```bash
export MONGODB_URL="mongodb+srv://admin:admin@cluster0.t5mooil.mongodb.net/dirsearch?appName=Cluster0"
```

### Domain Collection Naming
- URL: `https://example.com/path` → Collection: `scans_example_com`
- URL: `http://test.org` → Collection: `scans_test_org`
- Invalid URLs → Collection: `scans_unknown`

### Benefits
1. **Scalability**: Each domain isolated in its own collection
2. **Performance**: Faster queries per domain
3. **Flexibility**: Easy to add new domains without schema changes
4. **NoSQL**: Document-based storage for complex scan data

## Migration Notes
- All existing SQLite data will be migrated to MongoDB format
- Legacy function compatibility maintained for existing code
- Wordlists automatically loaded from `dirsearch/db` directory
- Connection testing and error handling implemented

## Dependencies
- Added: `pymongo>=4.0.0`
- Removed: `Flask-SQLAlchemy`, `SQLAlchemy`
