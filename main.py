import logging
import analyzer
# import reporter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    logging.info("Starting S3 Bucket Security Analyzer...")
    config = analyzer.load_config()
    if not config:
        exit(1)

    s3_client = analyzer.get_s3_client()
    if not s3_client:
        logging.critical("Failed to create S3 client. Check AWS credentials and permissions.")
        exit(1)

    buckets = analyzer.list_buckets(s3_client)

    if buckets:
        logging.info(f"Successfully retrieved {len(buckets)} buckets. Analysis phase next.")
        # analysed_data = analyzer.analyze_buckets(s3_client, buckets, config)
        # reporter.generate_report(analysed_data)
    else:
        logging.warning("No buckets retrieved or an error occurred.")

    logging.info("S3 Bucket Security Analyzer finished.")