#!/bin/bash

# Deploy Backend on EC2 (Run this script ON the EC2 instance)
# This script builds and runs the Docker container directly on EC2 with DynamoDB
# No need for Docker on your local machine!

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
FRONTEND_URL=${1:-"https://ynp01-s3-frontend2.s3.amazonaws.com"}
AWS_REGION=${2:-"us-east-1"}
CONTAINER_NAME="notification-platform-backend"
IMAGE_NAME="notification-backend:latest"

# DynamoDB Configuration
APPLICATIONS_TABLE="${APPLICATIONS_TABLE:-applications}"
API_KEYS_TABLE="${API_KEYS_TABLE:-api_keys}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Backend Deployment on EC2 (DynamoDB)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Validate frontend URL
if [ "$FRONTEND_URL" = "*" ]; then
    echo -e "${YELLOW}WARNING: CORS is set to allow ALL origins (development mode)${NC}"
    echo -e "${YELLOW}For production, provide your S3 bucket URL as an argument${NC}"
    echo -e "${YELLOW}Usage: ./deploy-on-ec2.sh https://your-bucket.s3.amazonaws.com [AWS_REGION]${NC}"
    echo ""
else
    echo -e "${GREEN}CORS will be configured for: ${FRONTEND_URL}${NC}"
    echo -e "${GREEN}AWS Region: ${AWS_REGION}${NC}"
    echo -e "${GREEN}DynamoDB Tables: ${APPLICATIONS_TABLE}, ${API_KEYS_TABLE}${NC}"
    echo ""
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed on this EC2 instance${NC}"
    echo -e "${YELLOW}Please install Docker first:${NC}"
    echo "  sudo yum update -y"
    echo "  sudo yum install docker -y"
    echo "  sudo service docker start"
    echo "  sudo usermod -a -G docker ec2-user"
    echo "  # Then log out and log back in"
    exit 1
fi

# Check if Docker daemon is running
if ! docker ps &> /dev/null; then
    echo -e "${YELLOW}Docker daemon is not running. Starting Docker...${NC}"
    sudo service docker start
    sleep 2
fi

echo -e "${YELLOW}Step 1: Stopping old container (if exists)...${NC}"
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true
echo -e "${GREEN}✓ Old container removed${NC}"
echo ""

echo -e "${YELLOW}Step 2: Building Docker image...${NC}"
docker build -t $IMAGE_NAME .
echo -e "${GREEN}✓ Docker image built successfully${NC}"
echo ""

echo -e "${YELLOW}Step 3: Checking for IAM role...${NC}"
# Check if EC2 instance has IAM role attached
if curl -s -f -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /dev/null 2>&1; then
    ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
    echo -e "${GREEN}✓ IAM role detected: $ROLE_NAME${NC}"
    echo -e "${GREEN}  Container will use EC2 instance IAM role for AWS credentials${NC}"
else
    echo -e "${YELLOW}⚠ No IAM role detected on this EC2 instance${NC}"
    echo -e "${YELLOW}  Container will need AWS credentials via environment variables or mounted credentials${NC}"
    echo -e "${YELLOW}  For production, it's recommended to attach an IAM role to the EC2 instance${NC}"
fi
echo ""

echo -e "${YELLOW}Step 4: Starting new container with DynamoDB configuration...${NC}"
docker run -d \
  --name $CONTAINER_NAME \
  --restart unless-stopped \
  -p 8001:8001 \
  -e AWS_REGION="$AWS_REGION" \
  -e APPLICATIONS_TABLE="$APPLICATIONS_TABLE" \
  -e API_KEYS_TABLE="$API_KEYS_TABLE" \
  -e ALLOWED_ORIGINS="$FRONTEND_URL" \
  $IMAGE_NAME

echo -e "${GREEN}✓ Container started successfully${NC}"
echo ""

# Wait for container to be healthy
echo -e "${YELLOW}Step 5: Waiting for container to be healthy...${NC}"
sleep 5

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container failed to start${NC}"
    echo -e "${YELLOW}Container logs:${NC}"
    docker logs $CONTAINER_NAME
    echo ""
    echo -e "${RED}Common issues:${NC}"
    echo -e "${YELLOW}1. NoCredentialsError: EC2 instance needs IAM role with DynamoDB permissions${NC}"
    echo -e "${YELLOW}2. Check logs above for specific error messages${NC}"
    echo -e "${YELLOW}3. See AWS_CREDENTIALS_SETUP.md for detailed troubleshooting${NC}"
    exit 1
fi

# Test health endpoint
echo ""
echo -e "${YELLOW}Step 6: Testing health endpoint...${NC}"
sleep 2
if curl -f http://localhost:8001/health &> /dev/null; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${YELLOW}⚠ Health check not ready yet (checking logs...)${NC}"
    echo ""
    docker logs --tail 20 $CONTAINER_NAME
    echo ""
    echo -e "${YELLOW}If you see 'NoCredentialsError', see AWS_CREDENTIALS_SETUP.md${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${GREEN}Container Status:${NC}"
docker ps | grep $CONTAINER_NAME || echo "Container not found"
echo ""
echo -e "${GREEN}Configuration:${NC}"
echo "  - Container Name: $CONTAINER_NAME"
echo "  - Port: 8001"
echo "  - AWS Region: $AWS_REGION"
echo "  - DynamoDB Tables: $APPLICATIONS_TABLE, $API_KEYS_TABLE"
echo "  - CORS Origins: $FRONTEND_URL"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "  - Backend now uses DynamoDB (not SQLite)"
echo "  - Ensure EC2 instance has IAM role with DynamoDB permissions"
echo "  - Tables will be auto-created on first run"
echo ""
echo -e "${GREEN}Useful Commands:${NC}"
echo "  View logs:        docker logs -f $CONTAINER_NAME"
echo "  Stop container:   docker stop $CONTAINER_NAME"
echo "  Start container:  docker start $CONTAINER_NAME"
echo "  Restart:          docker restart $CONTAINER_NAME"
echo "  Remove:           docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
echo ""
echo -e "${GREEN}Test Endpoints:${NC}"
echo "  Health:           curl http://localhost:8001/health"
echo "  Root:             curl http://localhost:8001/"
echo "  Applications:     curl http://localhost:8001/apps"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Test the endpoints above"
echo "  2. Ensure EC2 Security Group allows port 8001"
echo "  3. Verify EC2 IAM role has DynamoDB permissions"
echo "  4. Update frontend .env.local with this EC2 IP"
echo "  5. Rebuild and redeploy frontend to S3"
echo ""

