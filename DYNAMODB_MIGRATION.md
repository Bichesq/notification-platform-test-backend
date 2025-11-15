# DynamoDB Migration Guide

## Overview

This document describes the migration from SQLite/SQLAlchemy to AWS DynamoDB for the notification platform backend.

## Migration Summary

### What Changed

1. **Database Layer**: Replaced SQLAlchemy ORM with boto3 DynamoDB client/resource
2. **Data Models**: Converted from relational tables to DynamoDB tables with partition/sort keys
3. **Dependencies**: Replaced `sqlalchemy` with `boto3` in requirements.txt
4. **Configuration**: Updated environment variables from `DATABASE_URL` to AWS/DynamoDB settings

### DynamoDB Table Design

#### Applications Table
- **Table Name**: `applications` (configurable via `APPLICATIONS_TABLE` env var)
- **Partition Key**: `id` (String - UUID)
- **Attributes**:
  - `id`: String (UUID)
  - `name`: String
  - `application_id`: String
  - `email`: String
  - `domain`: String
  - `created_at`: String (ISO 8601 datetime)
  - `updated_at`: String (ISO 8601 datetime)
- **Global Secondary Index**:
  - `application_id-index`: For querying by application_id

#### API Keys Table
- **Table Name**: `api_keys` (configurable via `API_KEYS_TABLE` env var)
- **Partition Key**: `app_id` (String)
- **Sort Key**: `id` (String - UUID)
- **Attributes**:
  - `app_id`: String (references Applications.id)
  - `id`: String (UUID)
  - `key_hash`: String (SHA-256 hash)
  - `name`: String
  - `created_at`: String (ISO 8601 datetime)
  - `expires_at`: String (ISO 8601 datetime, nullable)
  - `last_used_at`: String (ISO 8601 datetime, nullable)
  - `is_active`: Boolean
- **Global Secondary Index**:
  - `key_hash-index`: For fast API key verification

## Configuration

### Environment Variables

```bash
# AWS Configuration
AWS_REGION=us-east-1

# For local DynamoDB development (optional)
DYNAMODB_ENDPOINT=http://localhost:8000

# DynamoDB Table Names
APPLICATIONS_TABLE=applications
API_KEYS_TABLE=api_keys

# CORS Configuration (unchanged)
ALLOWED_ORIGINS=*
```

### AWS Credentials

The application uses boto3, which requires AWS credentials. You can provide credentials in several ways:

1. **IAM Role** (Recommended for EC2/ECS):
   - Attach an IAM role to your EC2 instance or ECS task with DynamoDB permissions
   - No additional configuration needed

2. **Environment Variables**:
   ```bash
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   ```

3. **AWS Credentials File**:
   - Mount `~/.aws/credentials` into the Docker container
   - See docker-compose.yml for example

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:DescribeTable",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/applications",
        "arn:aws:dynamodb:*:*:table/applications/index/*",
        "arn:aws:dynamodb:*:*:table/api_keys",
        "arn:aws:dynamodb:*:*:table/api_keys/index/*"
      ]
    }
  ]
}
```

## Deployment

### 1. Update Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
# Edit .env with your AWS configuration
```

### 3. Initialize DynamoDB Tables

Tables are automatically created on application startup. The application will:
- Create `applications` table if it doesn't exist
- Create `api_keys` table if it doesn't exist
- Create necessary Global Secondary Indexes
- Wait for tables to become active

### 4. Run the Application

**Local Development**:
```bash
python server.py
```

**Docker**:
```bash
docker-compose up -d
```

**EC2 Deployment**:
- Ensure EC2 instance has an IAM role with DynamoDB permissions
- Deploy using existing deployment scripts
- Update environment variables in deployment configuration

## Data Migration (Optional)

If you have existing SQLite data to migrate:

1. Export data from SQLite
2. Transform to DynamoDB format
3. Use AWS CLI or boto3 to import

Example migration script structure:
```python
# Read from SQLite
# Transform IDs to UUIDs
# Convert datetime to ISO strings
# Write to DynamoDB using batch_write_item
```

## Testing

All existing API endpoints remain unchanged:
- `POST /app` - Create application
- `GET /apps` - List applications
- `GET /app/{app_id}` - Get application
- `DELETE /app/{app_id}` - Delete application
- `POST /app/{app_id}/api-key` - Generate API key
- `GET /app/{app_id}/api-keys` - List API keys
- `DELETE /app/{app_id}/api-key/{key_id}` - Revoke API key
- `GET /protected` - Protected route
- `POST /verify-key` - Verify API key

## Rollback

To rollback to SQLite:
1. Restore `server.py` from git history
2. Update `requirements.txt` to use `sqlalchemy`
3. Restore `.env` with `DATABASE_URL`
4. Redeploy

## Performance Considerations

- DynamoDB provides better scalability than SQLite
- GSIs enable fast lookups without table scans
- Consider using DynamoDB on-demand pricing for variable workloads
- Monitor read/write capacity units if using provisioned throughput

## Cost Optimization

- Tables are created with 5 RCU/WCU (provisioned)
- Consider switching to on-demand billing for unpredictable workloads
- Monitor usage and adjust capacity as needed

