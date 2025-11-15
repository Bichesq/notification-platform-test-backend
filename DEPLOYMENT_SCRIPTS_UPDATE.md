# Deployment Scripts Update for DynamoDB Migration

## Overview

The deployment scripts have been updated to support the DynamoDB migration. All SQLite-specific configurations have been removed and replaced with DynamoDB environment variables.

## Updated Scripts

### 1. `deploy-to-ec2.sh`

**Purpose**: Deploy backend from local machine to EC2 instance

**Changes Made**:
- ✅ Removed SQLite `DATABASE_URL` environment variable
- ✅ Removed volume mount for SQLite data directory (`~/notification-platform-data`)
- ✅ Added AWS region parameter (default: `us-east-1`)
- ✅ Added DynamoDB environment variables:
  - `AWS_REGION`
  - `APPLICATIONS_TABLE`
  - `API_KEYS_TABLE`
- ✅ Updated deployment instructions to mention IAM role requirements
- ✅ Removed data directory creation step

**New Usage**:
```bash
./deploy-to-ec2.sh <EC2_IP> [FRONTEND_URL] [AWS_REGION]

# Examples:
./deploy-to-ec2.sh 54.87.39.36 https://my-bucket.s3.amazonaws.com
./deploy-to-ec2.sh 54.87.39.36 https://my-bucket.s3.amazonaws.com us-west-2
```

**Environment Variables Passed to Container**:
- `AWS_REGION` - AWS region for DynamoDB (default: us-east-1)
- `APPLICATIONS_TABLE` - DynamoDB table name for applications (default: applications)
- `API_KEYS_TABLE` - DynamoDB table name for API keys (default: api_keys)
- `ALLOWED_ORIGINS` - CORS origins

### 2. `deploy-on-ec2.sh`

**Purpose**: Deploy backend directly on EC2 instance (run this script ON the EC2 instance)

**Changes Made**:
- ✅ Removed SQLite `DATABASE_URL` environment variable
- ✅ Removed volume mount for SQLite data directory
- ✅ Removed data directory creation step
- ✅ Added AWS region parameter (default: `us-east-1`)
- ✅ Added DynamoDB environment variables:
  - `AWS_REGION`
  - `APPLICATIONS_TABLE`
  - `API_KEYS_TABLE`
- ✅ Updated deployment instructions to mention IAM role requirements
- ✅ Updated test endpoints to use correct port (8001)

**New Usage**:
```bash
./deploy-on-ec2.sh [FRONTEND_URL] [AWS_REGION]

# Examples:
./deploy-on-ec2.sh https://my-bucket.s3.amazonaws.com
./deploy-on-ec2.sh https://my-bucket.s3.amazonaws.com us-west-2
```

**Environment Variables Passed to Container**:
- `AWS_REGION` - AWS region for DynamoDB (default: us-east-1)
- `APPLICATIONS_TABLE` - DynamoDB table name for applications (default: applications)
- `API_KEYS_TABLE` - DynamoDB table name for API keys (default: api_keys)
- `ALLOWED_ORIGINS` - CORS origins

## Prerequisites for Deployment

### 1. EC2 Instance IAM Role

The EC2 instance MUST have an IAM role attached with DynamoDB permissions. Create a role with this policy:

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

**To attach IAM role to EC2 instance**:
1. Go to EC2 Console
2. Select your instance
3. Actions → Security → Modify IAM role
4. Select the role with DynamoDB permissions
5. Save

### 2. Security Group Configuration

Ensure your EC2 Security Group allows:
- Inbound TCP port 8001 (or 80 if using port mapping) from 0.0.0.0/0 or your frontend's IP
- Inbound TCP port 22 for SSH

### 3. Docker Installation

Docker must be installed on the EC2 instance:
```bash
sudo yum update -y
sudo yum install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user
# Log out and log back in
```

## Deployment Process

### Option 1: Deploy from Local Machine

```bash
# Navigate to backend directory
cd test-frontend-backend/notification-platform-test-backend

# Make script executable
chmod +x deploy-to-ec2.sh

# Deploy
./deploy-to-ec2.sh <EC2_IP> <FRONTEND_URL> [AWS_REGION]
```

### Option 2: Deploy Directly on EC2

```bash
# SSH into EC2 instance
ssh -i your-key.pem ubuntu@<EC2_IP>

# Clone or upload your code
# Navigate to backend directory
cd notification-platform-test-backend

# Make script executable
chmod +x deploy-on-ec2.sh

# Deploy
./deploy-on-ec2.sh <FRONTEND_URL> [AWS_REGION]
```

## What Happens During Deployment

1. **Build Docker Image**: Creates Docker image with all dependencies
2. **Stop Old Container**: Stops and removes any existing container
3. **Start New Container**: Runs container with DynamoDB configuration
4. **Auto-Create Tables**: On first run, DynamoDB tables are automatically created
5. **Health Check**: Verifies the backend is running

## Verification

After deployment, verify the backend is working:

```bash
# Check container status
docker ps | grep notification-platform-backend

# View logs
docker logs -f notification-platform-backend

# Test health endpoint
curl http://localhost:8001/health

# Test root endpoint
curl http://localhost:8001/

# Test applications endpoint
curl http://localhost:8001/apps
```

## Troubleshooting

### Container Fails to Start

Check logs:
```bash
docker logs notification-platform-backend
```

Common issues:
- Missing IAM role with DynamoDB permissions
- Incorrect AWS region
- Network connectivity issues

### DynamoDB Tables Not Created

- Ensure IAM role has `dynamodb:CreateTable` permission
- Check CloudWatch logs for errors
- Verify AWS region is correct

### CORS Errors

- Ensure `ALLOWED_ORIGINS` matches your frontend URL exactly
- Include protocol (https://)
- No trailing slash

## Migration from SQLite

If you previously deployed with SQLite:

1. **Data Migration**: Export data from SQLite and import to DynamoDB (manual process)
2. **Remove Old Data**: The old SQLite database files in `~/notification-platform-data` are no longer used
3. **Redeploy**: Use updated deployment scripts

## Cost Considerations

- DynamoDB tables are created with 5 RCU/WCU (provisioned throughput)
- Monitor usage and adjust capacity as needed
- Consider on-demand billing for variable workloads

