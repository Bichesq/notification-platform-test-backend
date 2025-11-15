#!/bin/bash

# ============================================
# AWS ECS Infrastructure Setup Script
# ============================================
# This script sets up all required AWS resources for ECS deployment
# Usage: ./setup-ecs-infrastructure.sh [AWS_REGION]
# Example: ./setup-ecs-infrastructure.sh us-east-1

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION="${1:-us-east-1}"
ECR_REPO_NAME="notification-platform-backend"
ECS_CLUSTER_NAME="notification-platform-cluster"
ECS_SERVICE_NAME="notification-platform-service"
ECS_TASK_FAMILY="notification-platform-task"
LOG_GROUP_NAME="/ecs/notification-platform"
SECURITY_GROUP_NAME="notification-platform-sg"
IAM_ROLE_NAME="ecsTaskExecutionRole"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AWS ECS Infrastructure Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Region: ${BLUE}$AWS_REGION${NC}"
echo ""

# Get AWS Account ID
echo -e "${YELLOW}Getting AWS Account ID...${NC}"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}✓ AWS Account ID: $AWS_ACCOUNT_ID${NC}"
echo ""

# Step 1: Create ECR Repository
echo -e "${YELLOW}Step 1: Creating ECR Repository...${NC}"
if aws ecr describe-repositories --repository-names $ECR_REPO_NAME --region $AWS_REGION 2>/dev/null; then
    echo -e "${BLUE}ℹ ECR repository already exists${NC}"
else
    aws ecr create-repository \
        --repository-name $ECR_REPO_NAME \
        --region $AWS_REGION \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256
    echo -e "${GREEN}✓ ECR repository created${NC}"
fi
ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME"
echo -e "${GREEN}ECR URI: $ECR_URI${NC}"
echo ""

# Step 2: Create ECS Cluster
echo -e "${YELLOW}Step 2: Creating ECS Cluster...${NC}"
if aws ecs describe-clusters --clusters $ECS_CLUSTER_NAME --region $AWS_REGION --query 'clusters[0].status' --output text 2>/dev/null | grep -q "ACTIVE"; then
    echo -e "${BLUE}ℹ ECS cluster already exists${NC}"
else
    aws ecs create-cluster \
        --cluster-name $ECS_CLUSTER_NAME \
        --region $AWS_REGION \
        --capacity-providers FARGATE FARGATE_SPOT \
        --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1
    echo -e "${GREEN}✓ ECS cluster created${NC}"
fi
echo ""

# Step 3: Create CloudWatch Log Group
echo -e "${YELLOW}Step 3: Creating CloudWatch Log Group...${NC}"
if aws logs describe-log-groups --log-group-name-prefix $LOG_GROUP_NAME --region $AWS_REGION --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$LOG_GROUP_NAME"; then
    echo -e "${BLUE}ℹ Log group already exists${NC}"
else
    aws logs create-log-group \
        --log-group-name $LOG_GROUP_NAME \
        --region $AWS_REGION
    
    # Set retention to 7 days to save costs
    aws logs put-retention-policy \
        --log-group-name $LOG_GROUP_NAME \
        --retention-in-days 7 \
        --region $AWS_REGION
    echo -e "${GREEN}✓ CloudWatch log group created${NC}"
fi
echo ""

# Step 4: Create/Verify IAM Role for ECS Task Execution
echo -e "${YELLOW}Step 4: Setting up IAM Role...${NC}"
if aws iam get-role --role-name $IAM_ROLE_NAME 2>/dev/null; then
    echo -e "${BLUE}ℹ IAM role already exists${NC}"
else
    # Create the role
    aws iam create-role \
        --role-name $IAM_ROLE_NAME \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }'
    
    # Attach the required policy
    aws iam attach-role-policy \
        --role-name $IAM_ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
    
    echo -e "${GREEN}✓ IAM role created and policy attached${NC}"
    echo -e "${YELLOW}Waiting 10 seconds for IAM role to propagate...${NC}"
    sleep 10
fi
echo ""

# Step 5: Get VPC and Subnet Information
echo -e "${YELLOW}Step 5: Getting VPC and Subnet information...${NC}"
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text --region $AWS_REGION)
echo -e "${GREEN}✓ Default VPC ID: $VPC_ID${NC}"

SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query "Subnets[*].SubnetId" --output text --region $AWS_REGION)
SUBNET_ARRAY=($(echo $SUBNET_IDS | tr '\t' ' '))
echo -e "${GREEN}✓ Found ${#SUBNET_ARRAY[@]} subnets${NC}"
echo ""

# Step 6: Create Security Group
echo -e "${YELLOW}Step 6: Creating Security Group...${NC}"
SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query "SecurityGroups[0].GroupId" \
    --output text \
    --region $AWS_REGION 2>/dev/null)

if [ "$SG_ID" != "None" ] && [ -n "$SG_ID" ]; then
    echo -e "${BLUE}ℹ Security group already exists: $SG_ID${NC}"
else
    SG_ID=$(aws ec2 create-security-group \
        --group-name $SECURITY_GROUP_NAME \
        --description "Security group for notification platform backend" \
        --vpc-id $VPC_ID \
        --region $AWS_REGION \
        --query 'GroupId' \
        --output text)
    
    # Allow inbound traffic on port 8001
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 8001 \
        --cidr 0.0.0.0/0 \
        --region $AWS_REGION
    
    echo -e "${GREEN}✓ Security group created: $SG_ID${NC}"
fi
echo ""

# Step 7: Update and Register Task Definition
echo -e "${YELLOW}Step 7: Registering ECS Task Definition...${NC}"

# Create a temporary task definition file with actual values
TEMP_TASK_DEF=$(mktemp)
cat > $TEMP_TASK_DEF << EOF
{
  "family": "$ECS_TASK_FAMILY",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::$AWS_ACCOUNT_ID:role/$IAM_ROLE_NAME",
  "containerDefinitions": [{
    "name": "$ECR_REPO_NAME",
    "image": "$ECR_URI:latest",
    "essential": true,
    "portMappings": [{
      "containerPort": 8001,
      "protocol": "tcp"
    }],
    "environment": [
      {"name": "DATABASE_URL", "value": "sqlite:///./data/app.db"},
      {"name": "ALLOWED_ORIGINS", "value": "*"},
      {"name": "APP_PORT", "value": "8001"},
      {"name": "APP_HOST", "value": "0.0.0.0"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "$LOG_GROUP_NAME",
        "awslogs-region": "$AWS_REGION",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }]
}
EOF

aws ecs register-task-definition \
    --cli-input-json file://$TEMP_TASK_DEF \
    --region $AWS_REGION > /dev/null

rm $TEMP_TASK_DEF
echo -e "${GREEN}✓ Task definition registered${NC}"
echo ""

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}AWS Resources Created:${NC}"
echo -e "  ECR Repository: ${GREEN}$ECR_URI${NC}"
echo -e "  ECS Cluster: ${GREEN}$ECS_CLUSTER_NAME${NC}"
echo -e "  Task Definition: ${GREEN}$ECS_TASK_FAMILY${NC}"
echo -e "  Security Group: ${GREEN}$SG_ID${NC}"
echo -e "  Log Group: ${GREEN}$LOG_GROUP_NAME${NC}"
echo ""

echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo -e "${BLUE}1. Build and push initial Docker image to ECR:${NC}"
echo -e "   ${GREEN}aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com${NC}"
echo -e "   ${GREEN}docker build -t $ECR_REPO_NAME .${NC}"
echo -e "   ${GREEN}docker tag $ECR_REPO_NAME:latest $ECR_URI:latest${NC}"
echo -e "   ${GREEN}docker push $ECR_URI:latest${NC}"
echo ""

echo -e "${BLUE}2. Create ECS Service:${NC}"
echo -e "   ${GREEN}aws ecs create-service \\${NC}"
echo -e "   ${GREEN}  --cluster $ECS_CLUSTER_NAME \\${NC}"
echo -e "   ${GREEN}  --service-name $ECS_SERVICE_NAME \\${NC}"
echo -e "   ${GREEN}  --task-definition $ECS_TASK_FAMILY \\${NC}"
echo -e "   ${GREEN}  --desired-count 1 \\${NC}"
echo -e "   ${GREEN}  --launch-type FARGATE \\${NC}"
echo -e "   ${GREEN}  --network-configuration \"awsvpcConfiguration={subnets=[${SUBNET_ARRAY[0]}],securityGroups=[$SG_ID],assignPublicIp=ENABLED}\" \\${NC}"
echo -e "   ${GREEN}  --region $AWS_REGION${NC}"
echo ""

echo -e "${BLUE}3. Create IAM user for GitHub Actions:${NC}"
echo -e "   ${GREEN}aws iam create-user --user-name github-actions-ecs${NC}"
echo -e "   ${GREEN}aws iam create-access-key --user-name github-actions-ecs${NC}"
echo -e "   ${GREEN}aws iam attach-user-policy --user-name github-actions-ecs --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser${NC}"
echo -e "   ${GREEN}aws iam attach-user-policy --user-name github-actions-ecs --policy-arn arn:aws:iam::aws:policy/AmazonECS_FullAccess${NC}"
echo ""

echo -e "${BLUE}4. Add GitHub Secrets:${NC}"
echo -e "   Go to: ${GREEN}https://github.com/YOUR_USERNAME/YOUR_REPO/settings/secrets/actions${NC}"
echo -e "   Add these secrets:"
echo -e "   - ${YELLOW}AWS_ACCESS_KEY_ID${NC} (from step 3)"
echo -e "   - ${YELLOW}AWS_SECRET_ACCESS_KEY${NC} (from step 3)"
echo -e "   - ${YELLOW}AWS_REGION${NC} = $AWS_REGION"
echo ""

echo -e "${BLUE}5. Update workflow file:${NC}"
echo -e "   Edit ${GREEN}.github/workflows/deploy-to-ecs.yml${NC}"
echo -e "   Update these values if different:"
echo -e "   - AWS_REGION: $AWS_REGION"
echo -e "   - ECR_REPOSITORY: $ECR_REPO_NAME"
echo -e "   - ECS_SERVICE: $ECS_SERVICE_NAME"
echo -e "   - ECS_CLUSTER: $ECS_CLUSTER_NAME"
echo -e "   - ECS_TASK_DEFINITION: $ECS_TASK_FAMILY"
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}For detailed instructions, see:${NC}"
echo -e "  - ${BLUE}ECS_DEPLOYMENT_SETUP.md${NC}"
echo -e "  - ${BLUE}ECS_QUICK_START.md${NC}"
echo -e "${GREEN}========================================${NC}"

