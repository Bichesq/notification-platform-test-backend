#!/bin/bash

# ============================================
# AWS Credentials Verification Script
# ============================================
# This script helps verify that AWS credentials are properly configured
# for the notification platform backend to access DynamoDB

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}AWS Credentials Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check 1: Verify if running on EC2
echo -e "${YELLOW}Check 1: Detecting environment...${NC}"
if curl -s -f -m 2 http://169.254.169.254/latest/meta-data/instance-id > /dev/null 2>&1; then
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    echo -e "${GREEN}✓ Running on EC2 instance: $INSTANCE_ID${NC}"
    ON_EC2=true
else
    echo -e "${YELLOW}⚠ Not running on EC2 (local development)${NC}"
    ON_EC2=false
fi
echo ""

# Check 2: Verify IAM role (if on EC2)
if [ "$ON_EC2" = true ]; then
    echo -e "${YELLOW}Check 2: Verifying IAM role...${NC}"
    if curl -s -f -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /dev/null 2>&1; then
        ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
        echo -e "${GREEN}✓ IAM role attached: $ROLE_NAME${NC}"
        
        # Get credentials
        CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)
        ACCESS_KEY=$(echo $CREDS | grep -o '"AccessKeyId" : "[^"]*"' | cut -d'"' -f4)
        EXPIRATION=$(echo $CREDS | grep -o '"Expiration" : "[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$ACCESS_KEY" ]; then
            echo -e "${GREEN}  Access Key: ${ACCESS_KEY:0:10}...${NC}"
            echo -e "${GREEN}  Expires: $EXPIRATION${NC}"
        else
            echo -e "${RED}✗ Failed to retrieve credentials from IAM role${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ No IAM role attached to this EC2 instance${NC}"
        echo -e "${YELLOW}  Action required: Attach an IAM role with DynamoDB permissions${NC}"
        echo -e "${YELLOW}  See AWS_CREDENTIALS_SETUP.md for instructions${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Check 2: Checking for AWS credentials...${NC}"
    
    # Check environment variables
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
        echo -e "${GREEN}✓ AWS credentials found in environment variables${NC}"
        echo -e "${GREEN}  Access Key: ${AWS_ACCESS_KEY_ID:0:10}...${NC}"
    elif [ -f "$HOME/.aws/credentials" ]; then
        echo -e "${GREEN}✓ AWS credentials file found: $HOME/.aws/credentials${NC}"
    else
        echo -e "${RED}✗ No AWS credentials found${NC}"
        echo -e "${YELLOW}  Action required: Configure AWS credentials${NC}"
        echo -e "${YELLOW}  Run: aws configure${NC}"
        echo -e "${YELLOW}  Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables${NC}"
        exit 1
    fi
fi
echo ""

# Check 3: Verify AWS CLI is installed
echo -e "${YELLOW}Check 3: Verifying AWS CLI...${NC}"
if command -v aws &> /dev/null; then
    AWS_VERSION=$(aws --version 2>&1)
    echo -e "${GREEN}✓ AWS CLI installed: $AWS_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ AWS CLI not installed (optional but recommended)${NC}"
    echo -e "${YELLOW}  Install with: pip install awscli${NC}"
fi
echo ""

# Check 4: Test DynamoDB access
echo -e "${YELLOW}Check 4: Testing DynamoDB access...${NC}"
if command -v aws &> /dev/null; then
    AWS_REGION=${AWS_REGION:-us-east-1}
    
    if aws dynamodb list-tables --region $AWS_REGION > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Successfully connected to DynamoDB in region: $AWS_REGION${NC}"
        
        # List tables
        TABLES=$(aws dynamodb list-tables --region $AWS_REGION --query 'TableNames' --output text)
        if [ -n "$TABLES" ]; then
            echo -e "${GREEN}  Existing tables: $TABLES${NC}"
        else
            echo -e "${YELLOW}  No tables found (will be created on first run)${NC}"
        fi
    else
        echo -e "${RED}✗ Failed to connect to DynamoDB${NC}"
        echo -e "${YELLOW}  Possible issues:${NC}"
        echo -e "${YELLOW}  1. IAM role/user lacks DynamoDB permissions${NC}"
        echo -e "${YELLOW}  2. Incorrect AWS region${NC}"
        echo -e "${YELLOW}  3. Network connectivity issues${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ Skipping DynamoDB test (AWS CLI not installed)${NC}"
fi
echo ""

# Check 5: Verify Docker container can access credentials
echo -e "${YELLOW}Check 5: Checking Docker container...${NC}"
if docker ps | grep -q notification-platform-backend; then
    echo -e "${GREEN}✓ Backend container is running${NC}"
    
    # Test credentials inside container
    echo -e "${YELLOW}  Testing credentials inside container...${NC}"
    docker exec notification-platform-backend python3 -c "
import boto3
from botocore.exceptions import NoCredentialsError
try:
    dynamodb = boto3.client('dynamodb', region_name='us-east-1')
    response = dynamodb.list_tables()
    print('✓ Container can access DynamoDB')
    print('  Tables:', response.get('TableNames', []))
except NoCredentialsError:
    print('✗ Container cannot find AWS credentials')
    exit(1)
except Exception as e:
    print(f'⚠ Error: {e}')
    exit(1)
" 2>&1 | while IFS= read -r line; do
        if [[ $line == *"✓"* ]]; then
            echo -e "${GREEN}  $line${NC}"
        elif [[ $line == *"✗"* ]]; then
            echo -e "${RED}  $line${NC}"
        else
            echo -e "${YELLOW}  $line${NC}"
        fi
    done
else
    echo -e "${YELLOW}⚠ Backend container is not running${NC}"
    echo -e "${YELLOW}  Start the container first to test credentials${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verification Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Next steps:${NC}"
if [ "$ON_EC2" = true ]; then
    echo "  1. Deploy backend: ./deploy-on-ec2.sh <FRONTEND_URL>"
    echo "  2. Test endpoints: curl http://localhost:8001/health"
else
    echo "  1. Build image: docker build -t notification-backend:latest ."
    echo "  2. Run container: docker-compose -f docker-compose.local.yml up -d"
    echo "  3. Test endpoints: curl http://localhost:8001/health"
fi
echo ""

