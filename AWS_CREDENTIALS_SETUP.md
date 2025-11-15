# AWS Credentials Setup Guide

## Problem: `botocore.exceptions.NoCredentialsError`

### Why This Error Occurs

The `NoCredentialsError` happens because boto3 (AWS SDK for Python) cannot find valid AWS credentials to authenticate with DynamoDB. When running in a Docker container, boto3 looks for credentials in this order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Shared credentials file**: `~/.aws/credentials` (not accessible inside container by default)
3. **AWS config file**: `~/.aws/config`
4. **IAM role** (EC2 instance metadata): Only available when running on EC2 with attached IAM role
5. **Boto config file**: `/etc/boto.cfg` or `~/.boto`

**In Docker containers**, options 2-5 are typically not available unless explicitly configured, causing the error.

---

## Solution 1: EC2 IAM Role (RECOMMENDED for Production)

### Why This is Best for EC2 Deployment

- ✅ **Most secure**: No credentials stored in code or environment variables
- ✅ **Automatic rotation**: AWS manages credential rotation
- ✅ **No configuration needed**: Container automatically inherits EC2 instance credentials
- ✅ **Follows AWS best practices**

### Step 1: Create IAM Role with DynamoDB Permissions

1. **Go to IAM Console**: https://console.aws.amazon.com/iam/

2. **Create a new role**:
   - Click "Roles" → "Create role"
   - Select "AWS service" → "EC2"
   - Click "Next"

3. **Create and attach policy**:
   - Click "Create policy" → "JSON"
   - Paste this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:DescribeTable",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchWriteItem",
        "dynamodb:BatchGetItem"
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

4. **Name the policy**: `NotificationPlatformDynamoDBPolicy`

5. **Complete role creation**:
   - Go back to role creation
   - Search for and select `NotificationPlatformDynamoDBPolicy`
   - Click "Next"
   - Name the role: `NotificationPlatformEC2Role`
   - Add description: "Allows EC2 instance to access DynamoDB for notification platform"
   - Click "Create role"

### Step 2: Attach IAM Role to EC2 Instance

**Option A: Via AWS Console**

1. Go to EC2 Console: https://console.aws.amazon.com/ec2/
2. Select your EC2 instance
3. Click "Actions" → "Security" → "Modify IAM role"
4. Select `NotificationPlatformEC2Role`
5. Click "Update IAM role"

**Option B: Via AWS CLI**

```bash
# Get your instance ID
INSTANCE_ID="i-1234567890abcdef0"

# Attach the IAM role
aws ec2 associate-iam-instance-profile \
  --instance-id $INSTANCE_ID \
  --iam-instance-profile Name=NotificationPlatformEC2Role
```

### Step 3: Verify IAM Role is Attached

**SSH into your EC2 instance and run**:

```bash
# Check if IAM role is attached
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Should output the role name: NotificationPlatformEC2Role

# Get temporary credentials (should return JSON with AccessKeyId, SecretAccessKey, Token)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/NotificationPlatformEC2Role
```

If you see the role name and credentials, the IAM role is correctly attached! ✅

### Step 4: Deploy Backend

Now deploy using the standard script - **no additional configuration needed**:

```bash
./deploy-on-ec2.sh https://your-frontend-url.s3.amazonaws.com us-east-1
```

The Docker container will automatically use the EC2 instance's IAM role credentials.

---

## Solution 2: Local Development with AWS Credentials

### Option A: Pass Credentials via Environment Variables

**⚠️ WARNING**: Only use for local development, never commit credentials to git!

```bash
# Set your AWS credentials
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_REGION="us-east-1"

# Run Docker container with credentials
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  -e AWS_REGION="$AWS_REGION" \
  -e APPLICATIONS_TABLE="applications" \

### Option C: Use Local DynamoDB (Best for Offline Development)

**Install and run DynamoDB Local**:

```bash
# Using Docker
docker run -d \
  --name dynamodb-local \
  -p 8000:8000 \
  amazon/dynamodb-local:latest \
  -jar DynamoDBLocal.jar -sharedDb -inMemory

# Wait a few seconds for DynamoDB to start
sleep 3
```

**Run backend with local DynamoDB endpoint**:

```bash
docker run -d \
  --name notification-platform-backend \
  --link dynamodb-local \
  -p 8001:8001 \
  -e AWS_REGION="us-east-1" \
  -e AWS_ACCESS_KEY_ID="fakeAccessKey" \
  -e AWS_SECRET_ACCESS_KEY="fakeSecretKey" \
  -e DYNAMODB_ENDPOINT="http://dynamodb-local:8000" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest
```

**Using docker-compose** (easier):

```yaml
# docker-compose.local.yml
version: '3.8'

services:
  dynamodb-local:
    image: amazon/dynamodb-local:latest
    container_name: dynamodb-local
    ports:
      - "8000:8000"
    command: "-jar DynamoDBLocal.jar -sharedDb -inMemory"

  backend:
    build: .
    container_name: notification-platform-backend
    ports:
      - "8001:8001"
    environment:
      AWS_REGION: us-east-1
      AWS_ACCESS_KEY_ID: fakeAccessKey
      AWS_SECRET_ACCESS_KEY: fakeSecretKey
      DYNAMODB_ENDPOINT: http://dynamodb-local:8000
      APPLICATIONS_TABLE: applications
      API_KEYS_TABLE: api_keys
      ALLOWED_ORIGINS: "*"
    depends_on:
      - dynamodb-local
```

Run with:
```bash
docker-compose -f docker-compose.local.yml up -d
```

---

## Solution 3: Verification Commands

### Verify IAM Role on EC2

```bash
# SSH into EC2 instance
ssh -i your-key.pem ubuntu@<EC2_IP>

# Check if IAM role is attached
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Expected output: NotificationPlatformEC2Role (or your role name)

# Get credentials from instance metadata
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/NotificationPlatformEC2Role

# Expected output: JSON with AccessKeyId, SecretAccessKey, Token, Expiration
```

### Verify AWS Credentials in Docker Container

```bash
# Enter the running container
docker exec -it notification-platform-backend bash

# Inside container, check if boto3 can find credentials
python3 << 'EOF'
import boto3
from botocore.exceptions import NoCredentialsError

try:
    # Try to create a DynamoDB client
    dynamodb = boto3.client('dynamodb', region_name='us-east-1')

    # Try to list tables (this will fail if no credentials)
    response = dynamodb.list_tables()
    print("✅ Credentials found! Tables:", response.get('TableNames', []))
except NoCredentialsError:
    print("❌ No credentials found!")
except Exception as e:
    print(f"⚠️  Credentials found but error occurred: {e}")
EOF

# Exit container
exit
```

### Verify DynamoDB Access

```bash
# Test if backend can access DynamoDB
curl http://localhost:8001/health

# Expected output: {"status":"healthy"}

# Try to list applications (will create tables if they don't exist)
curl http://localhost:8001/apps

# Expected output: [] (empty array if no apps created yet)

# Check container logs for any errors
docker logs notification-platform-backend

# Look for:
# ✅ "Tables initialized successfully" or similar success message
# ❌ "NoCredentialsError" or "Unable to locate credentials"
```

### Verify DynamoDB Tables Were Created

**Using AWS CLI**:

```bash
# List DynamoDB tables
aws dynamodb list-tables --region us-east-1

# Expected output should include: "applications" and "api_keys"

# Describe applications table
aws dynamodb describe-table --table-name applications --region us-east-1

# Describe api_keys table
aws dynamodb describe-table --table-name api_keys --region us-east-1
```

**Using AWS Console**:

1. Go to DynamoDB Console: https://console.aws.amazon.com/dynamodb/
2. Select your region (e.g., us-east-1)
3. Click "Tables" in the left sidebar
4. You should see: `applications` and `api_keys` tables

---

## Troubleshooting

### Error: "NoCredentialsError" persists on EC2

**Possible causes**:

1. **IAM role not attached**: Verify with `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. **Container can't access instance metadata**: Docker networking issue
3. **IAM role lacks permissions**: Check IAM policy

**Solution for Docker networking issue**:

```bash
# Run container with host network mode (allows access to instance metadata)
docker run -d \
  --name notification-platform-backend \
  --network host \
  -e AWS_REGION="us-east-1" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest
```

### Error: "AccessDeniedException"

**Cause**: IAM role attached but lacks DynamoDB permissions

**Solution**: Update IAM role policy to include all required DynamoDB actions (see Solution 1)

### Error: "ResourceNotFoundException: Requested resource not found"

**Cause**: DynamoDB tables don't exist and IAM role lacks `dynamodb:CreateTable` permission

**Solution**: Add `dynamodb:CreateTable` to IAM policy, or create tables manually:

```bash
# Create applications table
aws dynamodb create-table \
  --table-name applications \
  --attribute-definitions \
    AttributeName=id,AttributeType=S \
    AttributeName=application_id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --global-secondary-indexes \
    "[{\"IndexName\":\"application_id-index\",\"KeySchema\":[{\"AttributeName\":\"application_id\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"},\"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}}]" \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --region us-east-1

# Create api_keys table
aws dynamodb create-table \
  --table-name api_keys \
  --attribute-definitions \
    AttributeName=app_id,AttributeType=S \
    AttributeName=id,AttributeType=S \
    AttributeName=key_hash,AttributeType=S \
  --key-schema \
    AttributeName=app_id,KeyType=HASH \
    AttributeName=id,KeyType=RANGE \
  --global-secondary-indexes \
    "[{\"IndexName\":\"key_hash-index\",\"KeySchema\":[{\"AttributeName\":\"key_hash\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"},\"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}}]" \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --region us-east-1
```

---

## Quick Reference

### EC2 Production Deployment (IAM Role)

```bash
# 1. Attach IAM role to EC2 instance (via AWS Console)
# 2. SSH into EC2
ssh -i your-key.pem ubuntu@<EC2_IP>

# 3. Deploy
cd notification-platform-test-backend
./deploy-on-ec2.sh https://your-frontend.s3.amazonaws.com us-east-1

# 4. Verify
curl http://localhost:8001/health
curl http://localhost:8001/apps
```

### Local Development (Mounted Credentials)

```bash
# 1. Configure AWS CLI
aws configure

# 2. Build image
docker build -t notification-backend:latest .

# 3. Run with mounted credentials
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -v ~/.aws:/root/.aws:ro \
  -e AWS_REGION="us-east-1" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest

# 4. Verify
curl http://localhost:8001/health
```

### Local Development (DynamoDB Local)

```bash
# Use docker-compose
docker-compose -f docker-compose.local.yml up -d

# Verify
curl http://localhost:8001/health
```

### Option B: Mount AWS Credentials File (RECOMMENDED for Local Development)

```bash
# Ensure you have AWS credentials configured locally
aws configure

# Run Docker container with mounted credentials
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -v ~/.aws:/root/.aws:ro \
  -e AWS_REGION="us-east-1" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest
```

**For Windows users**:
```bash
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -v %USERPROFILE%\.aws:/root/.aws:ro \
  -e AWS_REGION="us-east-1" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest
```


