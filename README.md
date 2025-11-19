# Notification Platform Backend

FastAPI-based backend service for managing applications and API keys.

## Features

- ✅ Application management (CRUD operations)
- ✅ API key generation and management
- ✅ **AWS DynamoDB database** (NoSQL, serverless, auto-scaling)
- ✅ CORS support for S3-hosted frontend
- ✅ Docker containerization
- ✅ Health check endpoints
- ✅ API key authentication
- ✅ AWS service integration (SES, SNS)

## Quick Start

### Prerequisites

1. **AWS Account** with DynamoDB access
2. **AWS Credentials** configured (IAM role or credentials file)
3. **Python 3.8+** installed
4. **Docker** (optional, for containerized deployment)

### Local Development

**Step 1: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Configure AWS credentials**

Option A - Use AWS CLI to configure credentials:
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

Option B - Set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

**Step 3: Set environment variables**
```bash
# Create .env file
cp .env.example .env

# Edit .env with your configuration
# AWS_REGION=us-east-1
# APPLICATIONS_TABLE=applications
# API_KEYS_TABLE=api_keys
# ALLOWED_ORIGINS=*
```

**Step 4: Run the server**
```bash
python server.py
```

Server will start at `http://localhost:8001`

**Note**: DynamoDB tables will be automatically created on first run!

### Docker Development

```bash
# Build image
docker build -t notification-backend .

# Run container with AWS credentials
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -e AWS_REGION=us-east-1 \
  -e APPLICATIONS_TABLE=applications \
  -e API_KEYS_TABLE=api_keys \
  -e ALLOWED_ORIGINS="*" \
  -v ~/.aws:/root/.aws:ro \
  notification-backend:latest
```

**Note**: The `-v ~/.aws:/root/.aws:ro` mounts your AWS credentials into the container.

**For EC2 deployment**: Use IAM role instead of mounting credentials.

### Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**Important**: Update `docker-compose.yml` to include AWS environment variables and credentials.

## Deployment

### Deploy to EC2

**Prerequisites:**
1. EC2 instance running (current: `13.221.91.36`)
2. **IAM role attached to EC2 instance** with DynamoDB permissions (see Configuration section)
3. Security group allows inbound traffic on port 80
4. SSH access to EC2 instance

**Quick Deploy:**
```bash
chmod +x deploy-to-ec2.sh
./deploy-to-ec2.sh <EC2_IP> <FRONTEND_URL>
```

**Example:**
```bash
./deploy-to-ec2.sh 13.221.91.36 https://my-bucket.s3.amazonaws.com
```

**Important**: Ensure the EC2 instance has an IAM role with DynamoDB permissions before deploying!

**Manual Deploy:**
See [EC2_DEPLOYMENT.md](EC2_DEPLOYMENT.md) for detailed instructions.

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# AWS Configuration
AWS_REGION=us-east-1

# DynamoDB Table Names
APPLICATIONS_TABLE=applications
API_KEYS_TABLE=api_keys

# For local DynamoDB development (optional)
# DYNAMODB_ENDPOINT=http://localhost:8000

# CORS - comma-separated origins
ALLOWED_ORIGINS=https://your-bucket.s3.amazonaws.com,https://your-domain.com

# Application
APP_PORT=8001
APP_HOST=0.0.0.0
```

### AWS Credentials

The application uses boto3 to connect to DynamoDB. Credentials can be provided in several ways:

**1. IAM Role (Recommended for EC2/ECS):**
- Attach an IAM role to your EC2 instance with DynamoDB permissions
- No additional configuration needed
- Most secure approach

**2. Environment Variables:**
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

**3. AWS Credentials File:**
- Mount `~/.aws/credentials` into the Docker container
- See `docker-compose.yml` for example

### Required IAM Permissions

Your EC2 instance or IAM user needs the following permissions:

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
    },
    {
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
```

**To attach IAM role to EC2 instance:**
1. Go to AWS Console → IAM → Roles
2. Create a new role with the above permissions
3. Go to EC2 → Instances → Select your instance
4. Actions → Security → Modify IAM role
5. Attach the created role

### CORS Configuration

**Development (allow all):**
```bash
ALLOWED_ORIGINS=*
```

**Production (specific origins):**
```bash
ALLOWED_ORIGINS=https://bucket.s3.amazonaws.com,https://domain.cloudfront.net
```

## API Endpoints

### Health & Info

- `GET /` - Basic health check with CORS info
- `GET /health` - Detailed health check

### Applications

- `GET /apps` - List all applications
- `POST /app` - Create new application
- `GET /app/{app_id}` - Get specific application
- `DELETE /app/{app_id}` - Delete application

### API Keys

- `POST /app/{app_id}/api-key` - Generate API key
- `GET /app/{app_id}/api-keys` - List application's API keys
- `DELETE /app/{app_id}/api-key/{key_id}` - Revoke API key
- `POST /verify-key` - Verify API key validity

### Protected Routes

- `GET /protected` - Example protected endpoint (requires API key)

## API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8001/docs`
- ReDoc: `http://localhost:8001/redoc`

## Testing

### Test Health Endpoint

```bash
curl http://localhost:8001/health
```

### Test Applications Endpoint

```bash
# List applications
curl http://localhost:80/apps

# Create application
curl -X POST "http://13.221.91.36:80/app" \
-H "Content-Type: application/json" \
-d '{
  "App_name": "TestApp",
  "Application": "com.example.testapp",
  "Email": "test@example.com",
  "Domain": "example.com"
}'

# Delete application
curl -X DELETE "http://13.221.91.36:80/app/1"

# Get specific application
curl http://13.221.91.36:80/app/1

# Generate API key
curl -X POST "http://localhost:80/app/{app_id}/api-key" \
-H "Content-Type: application/json" \
-d '{
  "name": "My API Key",
  "expires_at": "2025-12-31T23:59:59Z"
}'
# example
curl -X POST "http://13.221.91.36:80/app/app_001/api-key" \
-H "Content-Type: application/json" \
-d '{
  "name": "My API Key",
  "expires_at": "2025-12-31T23:59:59Z"
}'
```

### Test CORS

```bash
curl -H "Origin: https://your-bucket.s3.amazonaws.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS \
     http://localhost:8001/apps
```

## Database

### AWS DynamoDB

The application uses **AWS DynamoDB** as its database. DynamoDB is a fully managed NoSQL database service that provides:

- **Serverless**: No servers to manage
- **Auto-scaling**: Automatically scales to handle traffic
- **High availability**: Built-in replication across multiple availability zones
- **Performance**: Single-digit millisecond latency
- **Cost-effective**: Pay only for what you use

### DynamoDB Tables

The application uses two DynamoDB tables:

#### 1. Applications Table
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

#### 2. API Keys Table
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

### Table Initialization

Tables are **automatically created** on application startup if they don't exist. The application will:
1. Check if tables exist
2. Create tables with proper schema if missing
3. Create Global Secondary Indexes
4. Wait for tables to become active

No manual table creation is required!

### Backup & Recovery

DynamoDB provides built-in backup capabilities:

**Point-in-Time Recovery (PITR):**
```bash
# Enable PITR via AWS Console or CLI
aws dynamodb update-continuous-backups \
  --table-name applications \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
```

**On-Demand Backups:**
```bash
# Create backup
aws dynamodb create-backup \
  --table-name applications \
  --backup-name applications-backup-$(date +%Y%m%d)
```

### Local Development with DynamoDB

For local development, you can use DynamoDB Local:

```bash
# Run DynamoDB Local with Docker
docker run -d -p 8000:8000 amazon/dynamodb-local

# Set environment variable
export DYNAMODB_ENDPOINT=http://localhost:8000
```

## Monitoring

### Container Logs

```bash
docker logs -f notification-platform-backend
```

### Container Status

```bash
docker ps | grep notification-platform-backend
```

### Resource Usage

```bash
docker stats notification-platform-backend
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs notification-platform-backend

# Check if port is in use
sudo netstat -tulpn | grep 8001
```

### CORS Errors

```bash
# Check configured origins
curl http://localhost:8001/

# Update origins
docker stop notification-platform-backend
docker rm notification-platform-backend
# Restart with correct ALLOWED_ORIGINS
```

### Database Issues

```bash
# Check DynamoDB connection
curl http://localhost:8001/health

# Verify AWS credentials
aws sts get-caller-identity

# Check DynamoDB tables
aws dynamodb list-tables

# Describe table
aws dynamodb describe-table --table-name applications
```

### IAM Permission Issues

```bash
# If you see "AccessDeniedException" errors:
# 1. Verify IAM role is attached to EC2 instance
# 2. Check IAM policy includes required DynamoDB permissions
# 3. Verify table names match environment variables

# Test IAM permissions
aws dynamodb scan --table-name applications --max-items 1
```

## Development

### Project Structure

```
notification-platform-test-backend/
├── server.py              # Main FastAPI application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose configuration
├── .env.example          # Environment variables template
├── deploy-to-ec2.sh      # EC2 deployment script
├── EC2_DEPLOYMENT.md     # Deployment guide
└── README.md            # This file
```

### Adding New Endpoints

1. Define Pydantic models for request/response
2. Add route handler in `server.py`
3. Update API documentation
4. Test locally
5. Deploy

### Database Schema Changes

For DynamoDB schema changes:
1. Update table definitions in `server.py`
2. Tables are automatically created/updated on startup
3. For production, consider using AWS CloudFormation or Terraform
4. See [DYNAMODB_MIGRATION.md](DYNAMODB_MIGRATION.md) for migration details

## Security

### API Key Authentication

Protected routes require `X-API-Key` header:

```bash
curl -H "X-API-Key: sk_your_api_key_here" \
     http://localhost:8001/protected
```

### CORS Security

- Never use `ALLOWED_ORIGINS=*` in production
- Always specify exact origins
- Include protocol (http:// or https://)
- No trailing slashes

### Production Checklist

- [ ] Set specific ALLOWED_ORIGINS
- [ ] Use HTTPS (ALB or nginx)
- [ ] Attach IAM role to EC2 instance with DynamoDB permissions
- [ ] Enable DynamoDB Point-in-Time Recovery (PITR)
- [ ] Enable CloudWatch logging
- [ ] Set up DynamoDB automated backups
- [ ] Use Secrets Manager for sensitive data
- [ ] Restrict EC2 Security Group
- [ ] Enable VPC security
- [ ] Configure DynamoDB auto-scaling or use on-demand billing
- [ ] Set up CloudWatch alarms for DynamoDB throttling

## Performance

### Optimization Tips

1. **DynamoDB**: Already optimized for high performance
   - Single-digit millisecond latency
   - Auto-scaling enabled
   - Global Secondary Indexes for fast queries
2. Enable database connection pooling (boto3 handles this)
3. Add caching layer (Redis/ElastiCache) for frequently accessed data
4. Use CDN for static assets
5. Enable gzip compression
6. Optimize DynamoDB queries (use Query instead of Scan when possible)
7. Use DynamoDB on-demand billing for variable workloads

### Scaling

1. Use Application Load Balancer
2. Deploy multiple EC2 instances
3. Use Auto Scaling Groups
4. Implement health checks
5. DynamoDB automatically scales to handle traffic
6. Consider DynamoDB Global Tables for multi-region deployment

### DynamoDB Performance Considerations

- **Read/Write Capacity**: Tables are created with 5 RCU/WCU (provisioned)
- **On-Demand Mode**: Consider switching for unpredictable workloads
- **Global Secondary Indexes**: Enable fast lookups without table scans
- **Batch Operations**: Use batch_write_item for bulk operations
- **Query vs Scan**: Always use Query with partition key when possible

## License

[Your License Here]

## Support

For issues or questions:
- Check [EC2_DEPLOYMENT.md](EC2_DEPLOYMENT.md) 
- Check API documentation at `/docs`

## Related Documentation

- [DynamoDB Migration Guide](DYNAMODB_MIGRATION.md) - **Important: Read this for DynamoDB setup details**
- [EC2 Deployment Guide](EC2_DEPLOYMENT.md)
- [AWS Credentials Setup](AWS_CREDENTIALS_SETUP.md)
- [Integration Guide](../../INTEGRATION_GUIDE.md)
- [Quick Reference](../../QUICK_DEPLOYMENT_REFERENCE.md)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     AWS Cloud Infrastructure                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐              ┌────────────────────┐   │
│  │   AWS S3 Bucket  │              │   AWS EC2 Instance │   │
│  │  (Frontend)      │◄────CORS────►│  (Docker Backend)  │   │
│  │                  │              │                    │   │
│  │  - Next.js App   │              │  - FastAPI App     │   │
│  │  - Static Files  │              │  - Port 80         │   │
│  └──────────────────┘              └─────────┬──────────┘   │
│                                               │               │
│                                               │               │
│                                    ┌──────────▼──────────┐   │
│                                    │   AWS DynamoDB      │   │
│                                    │   (Database)        │   │
│                                    │                     │   │
│                                    │  - applications     │   │
│                                    │  - api_keys         │   │
│                                    │  - Auto-scaling     │   │
│                                    └─────────────────────┘   │
│                                               │               │
│                                    ┌──────────▼──────────┐   │
│                                    │  AWS Services       │   │
│                                    │  - SES (Email)      │   │
│                                    │  - SNS (SMS/Push)   │   │
│                                    └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Frontend (S3)** → Makes API calls to backend
2. **Backend (EC2)** → Processes requests, interacts with DynamoDB
3. **DynamoDB** → Stores application data, API keys, notifications
4. **AWS Services** → Backend uses SES for emails, SNS for SMS/push notifications

### Key Components

- **Frontend**: Static Next.js app hosted on S3
- **Backend**: FastAPI application in Docker container on EC2 (http://13.221.91.36:80)
- **Database**: DynamoDB tables (applications, api_keys)
- **AWS Services**: SES, SNS for notifications

