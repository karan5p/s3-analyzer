import boto3
import json
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

def analyze_buckets(s3_client, buckets, config):
    """
    Analyzes S3 buckets for security issues based on the provided configuration.
    
    Args:
        s3_client: Boto3 S3 client
        buckets: List of S3 bucket dictionaries
        config: Configuration dictionary with risk weights
        
    Returns:
        list: List of analyzed bucket data dictionaries with security findings
    """
    if not s3_client or not buckets:
        return []
        
    analyzed_data = []
    risk_weights = config.get('risk_weights', {})
    
    logger.info(f"Beginning security analysis of {len(buckets)} buckets")
    
    for bucket in buckets:
        bucket_name = bucket.get('Name', '')
        if not bucket_name:
            continue
            
        logger.info(f"Analyzing bucket: {bucket_name}")
        
        # Initialize bucket data
        bucket_data = {
            'name': bucket_name,
            'creation_date': bucket.get('CreationDate'),
            'region': None,  # Will be populated if available
            'issues': [],
            'risk_score': 0
        }
        
        try:
            # Get bucket location
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_data['region'] = location.get('LocationConstraint', 'us-east-1')
            
            # Check block public access settings
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                block_public_acls = public_access.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls', False)
                block_public_policy = public_access.get('PublicAccessBlockConfiguration', {}).get('BlockPublicPolicy', False)
                ignore_public_acls = public_access.get('PublicAccessBlockConfiguration', {}).get('IgnorePublicAcls', False)
                restrict_public_buckets = public_access.get('PublicAccessBlockConfiguration', {}).get('RestrictPublicBuckets', False)
                
                if not (block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets):
                    issue = {
                        'type': 'public_access_enabled',
                        'description': 'Block Public Access is not fully enabled',
                        'severity': risk_weights.get('public_access_enabled', 100),
                        'details': {
                            'BlockPublicAcls': block_public_acls,
                            'BlockPublicPolicy': block_public_policy,
                            'IgnorePublicAcls': ignore_public_acls,
                            'RestrictPublicBuckets': restrict_public_buckets
                        }
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # Public access block is not configured, which is a security issue
                    issue = {
                        'type': 'public_access_enabled',
                        'description': 'Block Public Access is not configured',
                        'severity': risk_weights.get('public_access_enabled', 100),
                        'details': {'error': 'NoSuchPublicAccessBlockConfiguration'}
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
                else:
                    logger.warning(f"Error checking public access block for {bucket_name}: {e}")
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        issue = {
                            'type': 'acl_public_read',
                            'description': 'Bucket ACL allows public access',
                            'severity': risk_weights.get('acl_public_read', 80),
                            'details': {'grant': grant}
                        }
                        bucket_data['issues'].append(issue)
                        bucket_data['risk_score'] += issue['severity']
                        break
            except ClientError as e:
                logger.warning(f"Error checking ACL for {bucket_name}: {e}")
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy.get('Policy', '{}')
                policy_json = json.loads(policy_str) if policy_str else {}
                
                # Very basic check for public policy - comprehensive check would need full policy evaluation
                if '"Principal": "*"' in policy_str or '"Principal": {"AWS": "*"}' in policy_str:
                    issue = {
                        'type': 'policy_public_read',
                        'description': 'Bucket policy may allow public access',
                        'severity': risk_weights.get('policy_public_read', 90),
                        'details': {'policy': policy_json}
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Error checking policy for {bucket_name}: {e}")
            
            # Check encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                # If we got here, encryption is enabled
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    issue = {
                        'type': 'encryption_disabled',
                        'description': 'Default encryption is not enabled',
                        'severity': risk_weights.get('encryption_disabled', 40),
                        'details': {'error': 'ServerSideEncryptionConfigurationNotFoundError'}
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
                else:
                    logger.warning(f"Error checking encryption for {bucket_name}: {e}")
            
            # Check versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    issue = {
                        'type': 'versioning_disabled',
                        'description': 'Bucket versioning is not enabled',
                        'severity': risk_weights.get('versioning_disabled', 20),
                        'details': {'versioning': versioning}
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
            except ClientError as e:
                logger.warning(f"Error checking versioning for {bucket_name}: {e}")
            
            # Check logging
            try:
                logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in logging_config:
                    issue = {
                        'type': 'logging_disabled',
                        'description': 'Bucket logging is not enabled',
                        'severity': risk_weights.get('logging_disabled', 15),
                        'details': {'logging': False}
                    }
                    bucket_data['issues'].append(issue)
                    bucket_data['risk_score'] += issue['severity']
            except ClientError as e:
                logger.warning(f"Error checking logging for {bucket_name}: {e}")
            
            analyzed_data.append(bucket_data)
            
        except ClientError as e:
            logger.error(f"Error analyzing bucket {bucket_name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error analyzing bucket {bucket_name}: {e}", exc_info=True)
    
    logger.info(f"Completed analysis of {len(analyzed_data)} buckets")
    return analyzed_data
