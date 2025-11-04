#!/bin/bash

# Deploy Backend on EC2 (Run this script ON the EC2 instance)
# This script builds and runs the Docker container directly on EC2
# No need for Docker on your local machine!

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
FRONTEND_URL=${1:-"https://ynp01-s3-frontend2.s3.amazonaws.com"}
CONTAINER_NAME="notification-platform-backend"
IMAGE_NAME="notification-backend:latest"
DATA_DIR="$HOME/notification-platform-data"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Backend Deployment on EC2${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Validate frontend URL
if [ "$FRONTEND_URL" = "*" ]; then
    echo -e "${YELLOW}WARNING: CORS is set to allow ALL origins (development mode)${NC}"
    echo -e "${YELLOW}For production, provide your S3 bucket URL as an argument${NC}"
    echo -e "${YELLOW}Usage: ./deploy-on-ec2.sh https://your-bucket.s3.amazonaws.com${NC}"
    echo ""
else
    echo -e "${GREEN}CORS will be configured for: ${FRONTEND_URL}${NC}"
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

echo -e "${YELLOW}Step 1: Creating data directory...${NC}"
mkdir -p "$DATA_DIR"
echo -e "${GREEN}✓ Data directory created: $DATA_DIR${NC}"
echo ""

echo -e "${YELLOW}Step 2: Stopping old container (if exists)...${NC}"
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true
echo -e "${GREEN}✓ Old container removed${NC}"
echo ""

echo -e "${YELLOW}Step 3: Building Docker image...${NC}"
docker build -t $IMAGE_NAME .
echo -e "${GREEN}✓ Docker image built successfully${NC}"
echo ""

echo -e "${YELLOW}Step 4: Starting new container...${NC}"
docker run -d \
  --name $CONTAINER_NAME \
  --restart unless-stopped \
  -p 8001:8001 \
  -v "$DATA_DIR:/app/data" \
  -e DATABASE_URL=sqlite:///./data/app.db \
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
    exit 1
fi

# Test health endpoint
echo ""
echo -e "${YELLOW}Step 6: Testing health endpoint...${NC}"
sleep 2
if curl -f http://localhost:8001/health &> /dev/null; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${YELLOW}⚠ Health check not ready yet (this is normal, may take a few seconds)${NC}"
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
echo "  - Data Directory: $DATA_DIR"
echo "  - CORS Origins: $FRONTEND_URL"
echo ""
echo -e "${GREEN}Useful Commands:${NC}"
echo "  View logs:        docker logs -f $CONTAINER_NAME"
echo "  Stop container:   docker stop $CONTAINER_NAME"
echo "  Start container:  docker start $CONTAINER_NAME"
echo "  Restart:          docker restart $CONTAINER_NAME"
echo "  Remove:           docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
echo ""
echo -e "${GREEN}Test Endpoints:${NC}"
echo "  Health:           curl http://localhost:80/health"
echo "  Root:             curl http://localhost:80/"
echo "  Applications:     curl http://localhost:80/apps"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Test the endpoints above"
echo "  2. Ensure EC2 Security Group allows port 80"
echo "  3. Update frontend .env.local with this EC2 IP"
echo "  4. Rebuild and redeploy frontend to S3"
echo ""

