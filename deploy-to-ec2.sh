#!/bin/bash

# ============================================
# EC2 Deployment Script for Backend Service
# ============================================
# This script deploys the backend to an EC2 instance with DynamoDB
# Usage: ./deploy-to-ec2.sh [EC2_IP] [FRONTEND_URL] [AWS_REGION]
# Example: ./deploy-to-ec2.sh 54.87.39.36 https://your-bucket.s3.amazonaws.com us-east-1

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
EC2_IP="${1:-}"
FRONTEND_URL="${2:-*}".
AWS_REGION="${3:-us-east-1}"
SSH_KEY="Bichesq-np-key.pem"
CONTAINER_NAME="notification-platform-backend"
IMAGE_NAME="notification-backend"
APP_PORT=8001
DEPLOY_DIR="notification-backend-deploy"

# DynamoDB Configuration
APPLICATIONS_TABLE="${APPLICATIONS_TABLE:-applications}"
API_KEYS_TABLE="${API_KEYS_TABLE:-api_keys}"

# Validate inputs
if [ -z "$EC2_IP" ]; then
    echo -e "${RED}Error: EC2 IP address is required${NC}"
    echo "Usage: $0 <EC2_IP> [FRONTEND_URL] [AWS_REGION]"
    echo "Example: $0 54.87.39.36 https://your-bucket.s3.amazonaws.com us-east-1"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Backend Deployment to EC2 (DynamoDB)${NC}"
echo -e "${GREEN}========================================${NC}"
echo "EC2 IP: $EC2_IP"
echo "Frontend URL: $FRONTEND_URL"
echo "AWS Region: $AWS_REGION"
echo "SSH Key: $SSH_KEY"
echo "Container: $CONTAINER_NAME"
echo "Port: $APP_PORT"
echo "DynamoDB Tables: $APPLICATIONS_TABLE, $API_KEYS_TABLE"
echo ""
echo -e "${YELLOW}Note: Ensure EC2 instance has IAM role with DynamoDB permissions${NC}"
echo ""

# Step 1: Prepare source code for transfer
echo -e "${YELLOW}Step 1: Preparing source code...${NC}"
echo "Creating temporary deployment package..."

# Create a temporary directory for deployment files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy necessary files (excluding venv, __pycache__, etc.)
cp server.py "$TEMP_DIR/"
cp requirements.txt "$TEMP_DIR/"
cp Dockerfile "$TEMP_DIR/"

echo -e "${GREEN}✓ Source code prepared${NC}"
echo ""

# Step 2: Transfer source code to EC2
echo -e "${YELLOW}Step 2: Transferring source code to EC2...${NC}"
echo "Using SSH key: $SSH_KEY"
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Create deployment directory on EC2 and transfer files
ssh -i "$SSH_KEY" ubuntu@$EC2_IP "mkdir -p ~/$DEPLOY_DIR"
scp -i "$SSH_KEY" "$TEMP_DIR/server.py" ubuntu@$EC2_IP:~/$DEPLOY_DIR/
scp -i "$SSH_KEY" "$TEMP_DIR/requirements.txt" ubuntu@$EC2_IP:~/$DEPLOY_DIR/
scp -i "$SSH_KEY" "$TEMP_DIR/Dockerfile" ubuntu@$EC2_IP:~/$DEPLOY_DIR/

echo -e "${GREEN}✓ Source code transferred to EC2${NC}"
echo ""

# Step 3: Build and deploy on EC2
echo -e "${YELLOW}Step 3: Building Docker image on EC2...${NC}"
ssh -i "$SSH_KEY" ubuntu@$EC2_IP << EOF
    set -e

    cd ~/$DEPLOY_DIR

    echo "Building Docker image on EC2..."
    docker build -f Dockerfile -t $IMAGE_NAME:latest .

    echo "Stopping old container (if exists)..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true

    echo "Starting new container with DynamoDB configuration..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p 80:$APP_PORT \
        -e AWS_REGION="$AWS_REGION" \
        -e APPLICATIONS_TABLE="$APPLICATIONS_TABLE" \
        -e API_KEYS_TABLE="$API_KEYS_TABLE" \
        -e ALLOWED_ORIGINS="$FRONTEND_URL" \
        $IMAGE_NAME:latest

    echo "Cleaning up old images..."
    docker image prune -f

    echo "Waiting for container to start..."
    sleep 5

    echo "Checking container status..."
    docker ps | grep $CONTAINER_NAME

    echo "Testing health endpoint..."
    curl -f http://localhost:$APP_PORT/health || echo "Health check failed (may take a few more seconds)"
EOF

echo -e "${GREEN}✓ Deployment completed${NC}"
echo ""

# Final instructions
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Backend is now running at: http://$EC2_IP:$APP_PORT"
echo "Health check: http://$EC2_IP:$APP_PORT/health"
echo "API docs: http://$EC2_IP:$APP_PORT/docs"
echo ""
echo -e "${YELLOW}Important: Make sure your EC2 instance has:${NC}"
echo "  1. IAM role with DynamoDB permissions (CreateTable, PutItem, GetItem, Query, Scan, UpdateItem, DeleteItem)"
echo "  2. Security Group allowing:"
echo "     - Inbound TCP port $APP_PORT from 0.0.0.0/0 (or your frontend's IP)"
echo "     - Inbound TCP port 22 for SSH"
echo ""
echo -e "${YELLOW}DynamoDB Configuration:${NC}"
echo "  - AWS Region: $AWS_REGION"
echo "  - Applications Table: $APPLICATIONS_TABLE"
echo "  - API Keys Table: $API_KEYS_TABLE"
echo "  - Tables will be auto-created on first run"
echo ""
echo -e "${YELLOW}CORS is configured for: $FRONTEND_URL${NC}"
echo "If you need to update CORS origins, redeploy with the correct FRONTEND_URL"
echo ""
echo -e "${YELLOW}Note:${NC} The backend now uses DynamoDB instead of SQLite."
echo "Ensure your EC2 instance has proper IAM permissions to access DynamoDB."
echo ""

