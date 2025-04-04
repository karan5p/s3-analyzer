import logging
import analyzer
import reporter
from db_handler import DatabaseHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    logging.info("Starting S3 Bucket Security Analyzer...")
    config = analyzer.load_config()
    if not config:
        exit(1)
        
    # Initialize database handler
    db_handler = DatabaseHandler()
    if not db_handler.connect():
        logging.warning("Failed to connect to database. Results won't be saved.")
    else:
        # Initialize database tables if they don't exist
        if not db_handler.initialize_tables():
            logging.warning("Failed to initialize database tables. Results won't be saved.")
            db_handler.close()
            db_handler = None
    
    s3_client = analyzer.get_s3_client()
    if not s3_client:
        logging.critical("Failed to create S3 client. Check AWS credentials and permissions.")
        if db_handler:
            db_handler.close()
        exit(1)
    
    # Create a new scan session in the database
    session_id = None
    if db_handler:
        session_id = db_handler.create_scan_session()
        if not session_id:
            logging.warning("Failed to create scan session in database.")
    
    # List S3 buckets
    buckets = analyzer.list_buckets(s3_client)
    
    if buckets:
        logging.info(f"Successfully retrieved {len(buckets)} buckets. Analysis phase next.")
        analysed_data = analyzer.analyze_buckets(s3_client, buckets, config)
        
        # Save analysis results to database
        if db_handler and session_id and analysed_data:
            total_issues = 0
            
            for bucket_data in analysed_data:
                # Save bucket information
                bucket_id = db_handler.save_bucket(
                    session_id=session_id,
                    name=bucket_data.get('name'),
                    region=bucket_data.get('region'),
                    creation_date=bucket_data.get('creation_date'),
                    risk_score=bucket_data.get('risk_score', 0)
                )
                
                if bucket_id:
                    # Save bucket issues
                    issues = bucket_data.get('issues', [])
                    for issue in issues:
                        db_handler.save_bucket_issue(
                            bucket_id=bucket_id,
                            issue_type=issue.get('type'),
                            description=issue.get('description'),
                            severity=issue.get('severity', 0),
                            details=issue.get('details')
                        )
                    
                    total_issues += len(issues)
            
            # Update scan session with results
            db_handler.update_scan_session(
                session_id=session_id,
                buckets_scanned=len(analysed_data),
                issues_found=total_issues
            )
            
            logging.info(f"Saved scan results to database (session ID: {session_id})")
        
        # Generate report
        reporter.generate_report(analysed_data)
    else:
        logging.warning("No buckets retrieved or an error occurred.")
        if db_handler and session_id:
            db_handler.update_scan_session(
                session_id=session_id,
                buckets_scanned=0,
                issues_found=0
            )
    
    # Close database connection
    if db_handler:
        db_handler.close()
    
    logging.info("S3 Bucket Security Analyzer finished.")