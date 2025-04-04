"""
AWS Security Group Analyzer - Database Handler
Handles all database operations for storing and retrieving security analysis results.
"""

import logging
import sqlite3
import yaml
import json
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class DatabaseHandler:
    """
    Handles database operations for the AWS Security Group Analyzer.
    Uses SQLite for simple file-based storage without requiring a database server.
    """
    
    def __init__(self, config_path='config.yaml'):
        self.config = self._load_db_config(config_path)
        self.connection = None
        
    def _load_db_config(self, config_path):
        # Load database configuration from YAML file
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Get sqlite configuration or use defaults
            if 'sqlite' not in config:
                logger.warning("SQLite configuration not found in config file. Using defaults.")
                return {
                    'db_file': 's3_analyzer.db'
                }
            return config['sqlite']
        except Exception as e:
            logger.error(f"Error loading database configuration: {e}", exc_info=True)
            return {'db_file': 's3_analyzer.db'}
            
    def connect(self):
        # Establish connection to the SQLite database
        if not self.config:
            logger.error("Cannot connect to database: Missing configuration")
            return False
            
        try:
            # Ensure the directory exists
            db_file = self.config.get('db_file', 's3_analyzer.db')
            db_dir = os.path.dirname(db_file)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)
                
            # Connect to SQLite database
            self.connection = sqlite3.connect(db_file)
            # Configure SQLite connection to return dictionaries instead of tuples
            self.connection.row_factory = sqlite3.Row
            logger.info(f"Successfully connected to SQLite database: {db_file}")
            return True
        except Exception as e:
            logger.error(f"Error connecting to database: {e}", exc_info=True)
            return False
            
    def initialize_tables(self):
        # Create necessary database tables if they don't exist
        if not self.connection:
            logger.error("Cannot initialize tables: No database connection")
            return False
            
        try:
            cursor = self.connection.cursor()
            
            # Create scan_sessions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT NOT NULL,
                aws_account_id TEXT,
                region TEXT,
                buckets_scanned INTEGER NOT NULL,
                issues_found INTEGER NOT NULL
            )
            """)
            
            # Create buckets table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS buckets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                region TEXT,
                creation_date TEXT,
                risk_score REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
            """)
            
            # Create bucket_issues table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS bucket_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_id INTEGER NOT NULL,
                issue_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity INTEGER NOT NULL,
                details TEXT,
                FOREIGN KEY (bucket_id) REFERENCES buckets(id)
            )
            """)
            
            self.connection.commit()
            logger.info("Database tables initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Error initializing database tables: {e}", exc_info=True)
            return False
    
    def create_scan_session(self, aws_account_id=None, region=None):
        # Create a new scan session record
        if not self.connection:
            logger.error("Cannot create scan session: No database connection")
            return None
            
        try:
            cursor = self.connection.cursor()
            sql = """
            INSERT INTO scan_sessions
            (scan_date, aws_account_id, region, buckets_scanned, issues_found)
            VALUES (?, ?, ?, ?, ?)
            """
            cursor.execute(sql, (
                datetime.now().isoformat(),
                aws_account_id,
                region,
                0,  # Will be updated after scan completes
                0   # Will be updated after scan completes
            ))
            
            self.connection.commit()
            session_id = cursor.lastrowid
            logger.info(f"Created scan session with ID: {session_id}")
            return session_id
        except Exception as e:
            logger.error(f"Error creating scan session: {e}", exc_info=True)
            if self.connection:
                self.connection.rollback()
            return None
    
    def update_scan_session(self, session_id, buckets_scanned, issues_found):
        # Update a scan session with results
        if not self.connection:
            logger.error("Cannot update scan session: No database connection")
            return False
            
        try:
            cursor = self.connection.cursor()
            sql = """
            UPDATE scan_sessions
            SET buckets_scanned = ?, issues_found = ?
            WHERE id = ?
            """
            cursor.execute(sql, (buckets_scanned, issues_found, session_id))
            
            self.connection.commit()
            logger.info(f"Updated scan session {session_id} with {buckets_scanned} buckets and {issues_found} issues")
            return True
        except Exception as e:
            logger.error(f"Error updating scan session: {e}", exc_info=True)
            if self.connection:
                self.connection.rollback()
            return False
    
    def save_bucket(self, session_id, name, region=None, creation_date=None, risk_score=0):
        # Save bucket information to the database
        if not self.connection:
            logger.error("Cannot save bucket: No database connection")
            return None
            
        try:
            cursor = self.connection.cursor()
            
            # Convert creation_date to string if it's a datetime
            if isinstance(creation_date, datetime):
                creation_date = creation_date.isoformat()
                
            sql = """
            INSERT INTO buckets
            (session_id, name, region, creation_date, risk_score)
            VALUES (?, ?, ?, ?, ?)
            """
            cursor.execute(sql, (
                session_id,
                name,
                region,
                creation_date,
                risk_score
            ))
            
            self.connection.commit()
            bucket_id = cursor.lastrowid
            logger.debug(f"Saved bucket {name} with ID: {bucket_id}")
            return bucket_id
        except Exception as e:
            logger.error(f"Error saving bucket {name}: {e}", exc_info=True)
            if self.connection:
                self.connection.rollback()
            return None
    
    def save_bucket_issue(self, bucket_id, issue_type, description, severity, details=None):
        # Save a bucket security issue to the database
        if not self.connection:
            logger.error("Cannot save bucket issue: No database connection")
            return None
            
        try:
            cursor = self.connection.cursor()
            
            # Convert details dict to JSON string
            details_json = json.dumps(details) if details else None
            
            sql = """
            INSERT INTO bucket_issues
            (bucket_id, issue_type, description, severity, details)
            VALUES (?, ?, ?, ?, ?)
            """
            cursor.execute(sql, (
                bucket_id,
                issue_type,
                description,
                severity,
                details_json
            ))
            
            self.connection.commit()
            issue_id = cursor.lastrowid
            logger.debug(f"Saved issue {issue_type} for bucket ID {bucket_id}")
            return issue_id
        except Exception as e:
            logger.error(f"Error saving bucket issue: {e}", exc_info=True)
            if self.connection:
                self.connection.rollback()
            return None
    
    def get_scan_history(self, limit=10):
        # Get history of recent scan sessions
        if not self.connection:
            logger.error("Cannot get scan history: No database connection")
            return []
            
        try:
            cursor = self.connection.cursor()
            sql = """
            SELECT * FROM scan_sessions
            ORDER BY scan_date DESC
            LIMIT ?
            """
            cursor.execute(sql, (limit,))
            result = [dict(row) for row in cursor.fetchall()]
            return result
        except Exception as e:
            logger.error(f"Error getting scan history: {e}", exc_info=True)
            return []
    
    def get_scan_results(self, session_id):
        # Get full results of a specific scan session
        if not self.connection:
            logger.error("Cannot get scan results: No database connection")
            return None
            
        try:
            cursor = self.connection.cursor()
            result = {
                'session': None,
                'buckets': [],
                'issues': {}
            }
            
            # Get session details
            cursor.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                result['session'] = dict(row)
            else:
                logger.warning(f"Scan session {session_id} not found")
                return None
            
            # Get buckets for this session
            cursor.execute("SELECT * FROM buckets WHERE session_id = ?", (session_id,))
            buckets = [dict(row) for row in cursor.fetchall()]
            result['buckets'] = buckets
            
            # Get issues for each bucket
            for bucket in buckets:
                bucket_id = bucket['id']
                cursor.execute("SELECT * FROM bucket_issues WHERE bucket_id = ?", (bucket_id,))
                issues = []
                for row in cursor.fetchall():
                    issue = dict(row)
                    # Parse JSON in details field
                    if issue['details']:
                        try:
                            issue['details'] = json.loads(issue['details'])
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse JSON details for issue ID {issue['id']}")
                    issues.append(issue)
                result['issues'][bucket_id] = issues
            
            return result
        except Exception as e:
            logger.error(f"Error getting scan results: {e}", exc_info=True)
            return None
    
    def get_high_risk_buckets(self, min_risk_score=50, limit=10):
        # Get buckets with high risk scores across all scan sessions
        if not self.connection:
            logger.error("Cannot get high risk buckets: No database connection")
            return []
            
        try:
            cursor = self.connection.cursor()
            sql = """
            SELECT b.*, s.scan_date 
            FROM buckets b
            JOIN scan_sessions s ON b.session_id = s.id
            WHERE b.risk_score >= ?
            ORDER BY b.risk_score DESC
            LIMIT ?
            """
            cursor.execute(sql, (min_risk_score, limit))
            buckets = [dict(row) for row in cursor.fetchall()]
            
            # Get issues for each bucket
            for bucket in buckets:
                cursor.execute("SELECT * FROM bucket_issues WHERE bucket_id = ?", (bucket['id'],))
                issues = []
                for row in cursor.fetchall():
                    issue = dict(row)
                    # Parse JSON in details field
                    if issue['details']:
                        try:
                            issue['details'] = json.loads(issue['details'])
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse JSON details for issue ID {issue['id']}")
                    issues.append(issue)
                bucket['issues'] = issues
            
            return buckets
        except Exception as e:
            logger.error(f"Error getting high risk buckets: {e}", exc_info=True)
            return []
            
    def close(self):
        # Close the database connection
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")