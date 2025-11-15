# AWS Credentials Error - Solution Summary

## Problem

You encountered: `botocore.exceptions.NoCredentialsError: Unable to locate credentials`

This error occurs because the Docker container running your backend cannot find AWS credentials to authenticate with DynamoDB.

---

## Quick Solutions

### ✅ Solution 1: EC2 with IAM Role (RECOMMENDED for Production)

**Best for**: Production deployment on EC2

**Steps**:

1. **Create IAM Role** (one-time setup):
   - Go to IAM Console → Roles → Create role
   - Select "EC2" as trusted entity
   - Create policy with DynamoDB permissions (see `AWS_CREDENTIALS_SETUP.md`)
   - Name it: `NotificationPlatformEC2Role`

2. **Attach IAM Role to EC2**:
   - EC2 Console → Select instance → Actions → Security → Modify IAM role
   - Select `NotificationPlatformEC2Role`
   - Click "Update IAM role"

3. **Verify IAM Role**:
   ```bash
   ssh -i your-key.pem ubuntu@<EC2_IP>
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
   # Should output: NotificationPlatformEC2Role
   ```

4. **Deploy**:
   ```bash
   ./deploy-on-ec2.sh https://your-frontend.s3.amazonaws.com
   ```

**Why this works**: Docker containers on EC2 automatically inherit the instance's IAM role credentials through the EC2 metadata service.

---

### ✅ Solution 2: Local Development with Mounted Credentials

**Best for**: Local testing with real AWS DynamoDB

**Steps**:

1. **Configure AWS CLI**:
   ```bash
   aws configure
   # Enter your AWS Access Key ID
   # Enter your AWS Secret Access Key
   # Enter region: us-east-1
   ```

2. **Run with mounted credentials**:
   ```bash
   docker build -t notification-backend:latest .
   
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

**Windows users**: Replace `~/.aws` with `%USERPROFILE%\.aws`

**Why this works**: Mounts your local AWS credentials file into the container.

---

### ✅ Solution 3: Local DynamoDB (No AWS Account Needed)

**Best for**: Offline development and testing

**Steps**:

1. **Use docker-compose**:
   ```bash
   docker-compose -f docker-compose.local.yml up -d
   ```

2. **Verify**:
   ```bash
   curl http://localhost:8001/health
   curl http://localhost:8001/apps
   ```

**Why this works**: Runs a local DynamoDB instance in Docker, no real AWS credentials needed.

---

## Verification

### Check if IAM Role is Attached (EC2 only)

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@<EC2_IP>

# Run verification script
chmod +x verify-aws-credentials.sh
./verify-aws-credentials.sh
```

### Check Container Logs

```bash
docker logs notification-platform-backend

# Look for:
# ✅ Success: "Tables initialized successfully"
# ❌ Error: "NoCredentialsError" or "Unable to locate credentials"
```

### Test Endpoints

```bash
# Health check
curl http://localhost:8001/health
# Expected: {"status":"healthy"}

# List applications
curl http://localhost:8001/apps
# Expected: [] (empty array)

# Check DynamoDB tables (if using real AWS)
aws dynamodb list-tables --region us-east-1
# Expected: applications, api_keys
```

---

## Files Created/Updated

| File | Purpose |
|------|---------|
| `AWS_CREDENTIALS_SETUP.md` | Comprehensive guide with all solutions |
| `docker-compose.local.yml` | Local development with DynamoDB Local |
| `verify-aws-credentials.sh` | Script to verify credentials are working |
| `deploy-on-ec2.sh` | Updated with IAM role detection |
| `deploy-to-ec2.sh` | Updated with IAM role detection |

---

## Troubleshooting

### Error persists on EC2

**Check IAM role**:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

If empty → No IAM role attached → Attach IAM role (see Solution 1)

### "AccessDeniedException"

IAM role exists but lacks permissions → Update IAM policy to include DynamoDB actions

### Container can't access instance metadata

Try running with host network:
```bash
docker run -d --network host \
  -e AWS_REGION="us-east-1" \
  -e APPLICATIONS_TABLE="applications" \
  -e API_KEYS_TABLE="api_keys" \
  notification-backend:latest
```

---

## IAM Policy Required

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

---

## Need More Help?

- **Detailed guide**: See `AWS_CREDENTIALS_SETUP.md`
- **Deployment guide**: See `DEPLOYMENT_SCRIPTS_UPDATE.md`
- **Migration guide**: See `DYNAMODB_MIGRATION.md`
- **Run verification**: `./verify-aws-credentials.sh`

