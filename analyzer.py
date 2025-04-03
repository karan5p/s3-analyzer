import boto3
import logging
import yaml
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

def load_config(config_path='config.yaml'):
    """Loads configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration {config_path}: {e}", exc_info=True)
        return None

def get_s3_client():
    """Creates an S3 client."""
    try:
        # Boto3 will automatically use credentials from env vars, ~/.aws/credentials, etc.
        s3 = boto3.client('s3')
        # Test connection/credentials by listing buckets
        s3.list_buckets()
        logger.info("Successfully created S3 client and verified credentials.")
        return s3
    except NoCredentialsError:
        logger.error("AWS credentials not found. Configure AWS CLI or environment variables.")
        return None
    except ClientError as e:
        # Handle potential errors like InvalidClientTokenId
        logger.error(f"AWS ClientError creating S3 client: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating S3 client: {e}", exc_info=True)
        return None

def list_buckets(s3_client):
    """Lists all S3 buckets accessible by the client."""
    if not s3_client: return []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logger.info(f"Found {len(buckets)} buckets.")
        return buckets
    except ClientError as e:
        logger.error(f"Error listing S3 buckets: {e}", exc_info=True)
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing S3 buckets: {e}", exc_info=True)
        return []

