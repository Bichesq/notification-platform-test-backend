"""
FastAPI Backend with API Key Generation
Complete backend service for managing applications and API keys
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from decimal import Decimal
import secrets
import hashlib
import os
import uuid
import boto3
from botocore.exceptions import ClientError

# Environment Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
# If ALLOWED_ORIGINS is "*", convert to list for CORS middleware
if ALLOWED_ORIGINS == ["*"]:
    ALLOWED_ORIGINS = ["*"]
else:
    # Strip whitespace from each origin
    ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS]

# DynamoDB setup
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
DYNAMODB_ENDPOINT = os.getenv("DYNAMODB_ENDPOINT")  # For local development
APPLICATIONS_TABLE = os.getenv("APPLICATIONS_TABLE", "applications")
API_KEYS_TABLE = os.getenv("API_KEYS_TABLE", "api_keys")

# Initialize DynamoDB resource
dynamodb_config = {"region_name": AWS_REGION}
if DYNAMODB_ENDPOINT:
    dynamodb_config["endpoint_url"] = DYNAMODB_ENDPOINT

dynamodb = boto3.resource("dynamodb", **dynamodb_config)
dynamodb_client = boto3.client("dynamodb", **dynamodb_config)


# Helper function to convert datetime to ISO string for DynamoDB
def datetime_to_str(dt: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO format string"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def str_to_datetime(s: Optional[str]) -> Optional[datetime]:
    """Convert ISO format string to datetime"""
    if s is None or s == "":
        return None
    return datetime.fromisoformat(s)


# Initialize DynamoDB tables
def init_dynamodb_tables():
    """Create DynamoDB tables if they don't exist"""
    try:
        # Create Applications table
        try:
            dynamodb.create_table(
                TableName=APPLICATIONS_TABLE,
                KeySchema=[
                    {"AttributeName": "id", "KeyType": "HASH"}  # Partition key
                ],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "application_id", "AttributeType": "S"}
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "application_id-index",
                        "KeySchema": [
                            {"AttributeName": "application_id", "KeyType": "HASH"}
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5
                }
            )
            print(f"Created table {APPLICATIONS_TABLE}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException":
                raise
            print(f"Table {APPLICATIONS_TABLE} already exists")

        # Create API Keys table
        try:
            dynamodb.create_table(
                TableName=API_KEYS_TABLE,
                KeySchema=[
                    {"AttributeName": "app_id", "KeyType": "HASH"},  # Partition key
                    {"AttributeName": "id", "KeyType": "RANGE"}  # Sort key
                ],
                AttributeDefinitions=[
                    {"AttributeName": "app_id", "AttributeType": "S"},
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "key_hash", "AttributeType": "S"}
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "key_hash-index",
                        "KeySchema": [
                            {"AttributeName": "key_hash", "KeyType": "HASH"}
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5
                }
            )
            print(f"Created table {API_KEYS_TABLE}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException":
                raise
            print(f"Table {API_KEYS_TABLE} already exists")

        # Wait for tables to be active
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)
        api_keys_table = dynamodb.Table(API_KEYS_TABLE)
        applications_table.wait_until_exists()
        api_keys_table.wait_until_exists()
        print("DynamoDB tables are ready")

    except Exception as e:
        print(f"Error initializing DynamoDB tables: {e}")
        raise


# Initialize tables on startup
init_dynamodb_tables()

# Pydantic Models
class ApplicationCreate(BaseModel):
    App_name: str = Field(..., min_length=1, max_length=255)
    Application: str
    Email: str
    Domain: str


class ApplicationResponse(BaseModel):
    id: str
    name: str
    application_id: str
    email: str
    domain: str
    created_at: datetime
    updated_at: datetime 


class APIKeyCreate(BaseModel):
    name: Optional[str] = None
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: str
    api_key: str  # Only returned on creation
    name: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]


class APIKeyInfo(BaseModel):
    id: str
    name: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    is_active: bool


# FastAPI App
app = FastAPI(
    title="Application API Key Manager",
    description="API for managing applications and their API keys",
    version="1.0.0"
)

# CORS middleware - configured via ALLOWED_ORIGINS environment variable
# For production, set ALLOWED_ORIGINS to your S3 bucket URL or CloudFront domain
# Example: ALLOWED_ORIGINS=https://your-bucket.s3.amazonaws.com,https://your-cloudfront-domain.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "Accept"],
    expose_headers=["Content-Type", "X-Total-Count"],
    max_age=3600,  # Cache preflight requests for 1 hour
)


# Dependency
def get_dynamodb():
    """Dependency to get DynamoDB resource"""
    return dynamodb


# Utility Functions
def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify an API key and return the key record if valid"""
    key_hash = hash_api_key(api_key)

    # Query the key_hash-index GSI
    api_keys_table = dynamodb.Table(API_KEYS_TABLE)

    try:
        response = api_keys_table.query(
            IndexName="key_hash-index",
            KeyConditionExpression="key_hash = :kh",
            ExpressionAttributeValues={":kh": key_hash}
        )

        items = response.get("Items", [])
        if not items:
            return None

        key_record = items[0]

        # Check if active
        if not key_record.get("is_active", False):
            return None

        # Check if expired
        expires_at_str = key_record.get("expires_at")
        if expires_at_str:
            expires_at = str_to_datetime(expires_at_str)
            if expires_at and expires_at < datetime.now(timezone.utc):
                return None

        # Update last used timestamp
        api_keys_table.update_item(
            Key={
                "app_id": key_record["app_id"],
                "id": key_record["id"]
            },
            UpdateExpression="SET last_used_at = :lut",
            ExpressionAttributeValues={
                ":lut": datetime_to_str(datetime.now(timezone.utc))
            }
        )

        return key_record

    except ClientError as e:
        print(f"Error verifying API key: {e}")
        return None


# Dependency for API key authentication
async def require_api_key(x_api_key: Optional[str] = Header(None)):
    """Dependency to require valid API key"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    key_record = verify_api_key(x_api_key)
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    return key_record


# Routes

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Application API Key Manager",
        "version": "1.0.0",
        "cors_origins": ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else "all origins (development mode)"
    }


@app.get("/health")
async def health_check():
    """Detailed health check endpoint"""
    return {
        "status": "healthy",
        "service": "Application API Key Manager",
        "version": "1.0.0",
        "database": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/app", response_model=ApplicationResponse, status_code=201)
async def create_application(app_data: ApplicationCreate):
    """Create a new application"""
    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)

        # Generate unique ID
        app_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        item = {
            "id": app_id,
            "name": app_data.App_name,
            "application_id": app_data.Application,
            "email": app_data.Email,
            "domain": app_data.Domain,
            "created_at": datetime_to_str(now),
            "updated_at": datetime_to_str(now)
        }

        applications_table.put_item(Item=item)

        # Return response
        return ApplicationResponse(
            id=app_id,
            name=app_data.App_name,
            application_id=app_data.Application,
            email=app_data.Email,
            domain=app_data.Domain,
            created_at=now,
            updated_at=now
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create application: {str(e)}")


@app.get("/apps", response_model=List[ApplicationResponse])
async def list_applications(skip: int = 0, limit: int = 100):
    print(f"[DEBUG] Received GET /apps with skip={skip}, limit={limit}")

    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)

        # Scan the table (for production, consider using pagination)
        response = applications_table.scan()
        items = response.get("Items", [])

        # Handle pagination if there are more items
        while "LastEvaluatedKey" in response:
            response = applications_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        # Convert to response models
        apps = []
        for item in items[skip:skip+limit]:
            apps.append(ApplicationResponse(
                id=item["id"],
                name=item["name"],
                application_id=item["application_id"],
                email=item["email"],
                domain=item.get("domain", ""),
                created_at=str_to_datetime(item["created_at"]),
                updated_at=str_to_datetime(item["updated_at"])
            ))

        print(f"[DEBUG] Returning {len(apps)} applications")
        return apps
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list applications: {str(e)}")


@app.get("/app/{app_id}", response_model=ApplicationResponse)
async def get_application(app_id: str):
    """Get a specific application"""
    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)

        response = applications_table.get_item(Key={"id": app_id})
        item = response.get("Item")

        if not item:
            raise HTTPException(status_code=404, detail="Application not found")

        return ApplicationResponse(
            id=item["id"],
            name=item["name"],
            application_id=item["application_id"],
            email=item["email"],
            domain=item.get("domain", ""),
            created_at=str_to_datetime(item["created_at"]),
            updated_at=str_to_datetime(item["updated_at"])
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get application: {str(e)}")


@app.delete("/app/{app_id}", status_code=204)
async def delete_application(app_id: str):
    """Delete an application and all its API keys"""
    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)
        api_keys_table = dynamodb.Table(API_KEYS_TABLE)

        # Check if application exists
        response = applications_table.get_item(Key={"id": app_id})
        if "Item" not in response:
            raise HTTPException(status_code=404, detail="Application not found")

        # Delete all API keys for this application
        keys_response = api_keys_table.query(
            KeyConditionExpression="app_id = :aid",
            ExpressionAttributeValues={":aid": app_id}
        )

        for key in keys_response.get("Items", []):
            api_keys_table.delete_item(
                Key={"app_id": app_id, "id": key["id"]}
            )

        # Delete the application
        applications_table.delete_item(Key={"id": app_id})

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete application: {str(e)}")


@app.post("/app/{app_id}/api-key", response_model=APIKeyResponse, status_code=201)
async def generate_api_key(
    app_id: str,
    key_data: APIKeyCreate = APIKeyCreate()
):
    """Generate a new API key for an application"""
    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)
        api_keys_table = dynamodb.Table(API_KEYS_TABLE)

        # Verify application exists
        app_response = applications_table.get_item(Key={"id": app_id})
        app = app_response.get("Item")
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")

        # Generate a secure random API key
        api_key = f"sk_{secrets.token_urlsafe(32)}"
        key_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # Store hashed version in database
        item = {
            "app_id": app_id,
            "id": key_id,
            "key_hash": hash_api_key(api_key),
            "name": key_data.name or f"API Key for {app['name']}",
            "created_at": datetime_to_str(now),
            "expires_at": datetime_to_str(key_data.expires_at) if key_data.expires_at else None,
            "last_used_at": None,
            "is_active": True
        }

        api_keys_table.put_item(Item=item)

        # Return the plain key (only time it's shown)
        return APIKeyResponse(
            id=key_id,
            api_key=api_key,
            name=item["name"],
            created_at=now,
            expires_at=key_data.expires_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate API key: {str(e)}")


@app.get("/app/{app_id}/api-keys", response_model=List[APIKeyInfo])
async def list_api_keys(app_id: str):
    """List all API keys for an application (without showing the actual keys)"""
    try:
        applications_table = dynamodb.Table(APPLICATIONS_TABLE)
        api_keys_table = dynamodb.Table(API_KEYS_TABLE)

        # Check if application exists
        app_response = applications_table.get_item(Key={"id": app_id})
        if "Item" not in app_response:
            raise HTTPException(status_code=404, detail="Application not found")

        # Query all API keys for this application
        response = api_keys_table.query(
            KeyConditionExpression="app_id = :aid",
            ExpressionAttributeValues={":aid": app_id}
        )

        keys = []
        for item in response.get("Items", []):
            keys.append(APIKeyInfo(
                id=item["id"],
                name=item.get("name"),
                created_at=str_to_datetime(item["created_at"]),
                expires_at=str_to_datetime(item.get("expires_at")),
                last_used_at=str_to_datetime(item.get("last_used_at")),
                is_active=item.get("is_active", False)
            ))

        return keys
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list API keys: {str(e)}")


@app.delete("/app/{app_id}/api-key/{key_id}", status_code=204)
async def revoke_api_key(app_id: str, key_id: str):
    """Revoke (deactivate) an API key"""
    try:
        api_keys_table = dynamodb.Table(API_KEYS_TABLE)

        # Get the key to verify it exists
        response = api_keys_table.get_item(
            Key={"app_id": app_id, "id": key_id}
        )

        if "Item" not in response:
            raise HTTPException(status_code=404, detail="API key not found")

        # Update is_active to False
        api_keys_table.update_item(
            Key={"app_id": app_id, "id": key_id},
            UpdateExpression="SET is_active = :ia",
            ExpressionAttributeValues={":ia": False}
        )

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke API key: {str(e)}")


@app.get("/protected")
async def protected_route(key_record: Dict[str, Any] = Depends(require_api_key)):
    """Example protected route that requires a valid API key"""
    return {
        "message": "Access granted!",
        "app_id": key_record["app_id"],
        "key_name": key_record.get("name")
    }


@app.post("/verify-key")
async def verify_key(x_api_key: str = Header(...)):
    """Verify if an API key is valid"""
    key_record = verify_api_key(x_api_key)
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    return {
        "valid": True,
        "app_id": key_record["app_id"],
        "key_name": key_record.get("name"),
        "expires_at": key_record.get("expires_at")
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
