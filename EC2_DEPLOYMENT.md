# EC2 Deployment Guide for Backend Service

This guide explains how to deploy the backend service to an EC2 instance to work with the S3-hosted frontend.

## Prerequisites

- EC2 instance running (Ubuntu 20.04+ or Amazon Linux 2)
- Docker installed on EC2 instance
- SSH access to EC2 instance
- EC2 Security Group configured (see below)

## Quick Deployment

### Option 1: Using the Deployment Script (Recommended)

```bash
# Make the script executable
chmod +x deploy-to-ec2.sh 

# Deploy with your EC2 IP and frontend URL
./deploy-to-ec2.sh <EC2_IP> <FRONTEND_URL>

# Example:
./deploy-to-ec2.sh 98.81.247.123 http://ynp01-s3-frontend2.s3-website-us-east-1.amazonaws.com/
```

### Option 2: Manual Deployment

#### Step 1: Build Docker Image Locally

```bash
cd notification-platform-test-backend
docker build -t notification-backend:latest .
```

#### Step 2: Save and Transfer Image

```bash
# Save image to tar file
docker save -o backend-image.tar notification-backend:latest

# Copy to EC2 (replace with your key and IP)
scp -i /path/to/your-key.pem backend-image.tar ubuntu@YOUR_EC2_IP:~/
```

#### Step 3: Deploy on EC2

SSH into your EC2 instance:

```bash
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_IP
```

Then run these commands on EC2:

```bash
# Load the Docker image
docker load -i ~/backend-image.tar

# Stop and remove old container (if exists)
docker stop notification-platform-backend 2>/dev/null || true
docker rm notification-platform-backend 2>/dev/null || true

# Create data directory for persistent storage
mkdir -p ~/notification-platform-data

# Run the container with environment variables
docker run -d \
  --name notification-platform-backend \
  --restart unless-stopped \
  -p 8001:8001 \
  -v ~/notification-platform-data:/app/data \
  -e DATABASE_URL=sqlite:///./data/app.db \
  -e ALLOWED_ORIGINS="https://your-bucket.s3.amazonaws.com,https://your-cloudfront-domain.cloudfront.net" \
  notification-backend:latest

# Verify container is running
docker ps | grep notification-platform-backend

# Check logs
docker logs notification-platform-backend

# Test health endpoint
curl http://localhost:8001/health
```

#### Step 4: Cleanup

```bash
# Remove the tar file
rm ~/backend-image.tar

# Clean up old Docker images
docker image prune -f
```

## Environment Variables

Configure these environment variables when running the container:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./app.db` | `sqlite:///./data/app.db` |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` | `https://bucket.s3.amazonaws.com,https://domain.com` |

### Setting ALLOWED_ORIGINS

**For Development (allow all origins):**
```bash
-e ALLOWED_ORIGINS="*"
```

**For Production (specific domains):**
```bash
-e ALLOWED_ORIGINS="https://your-bucket.s3.amazonaws.com,https://your-cloudfront-domain.cloudfront.net,https://yourdomain.com"
```

**Important:** 
- Use comma-separated values for multiple origins
- Include the protocol (http:// or https://)
- Do NOT include trailing slashes
- Do NOT include wildcards in production

## EC2 Security Group Configuration

Your EC2 Security Group must allow the following inbound rules:

| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| SSH | TCP | 22 | Your IP | SSH access |
| Custom TCP | TCP | 8001 | 0.0.0.0/0 | Backend API access |

### How to Configure Security Group:

1. Go to AWS Console → EC2 → Security Groups
2. Select your instance's security group
3. Click "Edit inbound rules"
4. Add the rules above
5. Save rules

## Verification

After deployment, verify the backend is working:

### 1. Check Container Status

```bash
docker ps
```

You should see `notification-platform-backend` running.

### 2. Check Container Logs

```bash
docker logs notification-platform-backend
```

Look for: `Application startup complete`

### 3. Test Health Endpoint

```bash
# From EC2 instance
curl http://localhost:8001/health

# From your local machine (replace with your EC2 IP)
curl http://YOUR_EC2_IP:8001/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Application API Key Manager",
  "version": "1.0.0",
  "database": "connected",
  "timestamp": "2025-11-04T12:00:00.000000"
}
```

### 4. Test CORS Configuration

```bash
# From your local machine
curl -H "Origin: https://your-bucket.s3.amazonaws.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS \
     http://YOUR_EC2_IP:8001/apps
```

You should see CORS headers in the response.

### 5. Test API Endpoints

```bash
# List applications
curl http://YOUR_EC2_IP:8001/apps

# Get API documentation
# Open in browser: http://YOUR_EC2_IP:8001/docs
```

## Updating the Deployment

To update the backend after making changes:

```bash
# Rebuild and redeploy
./deploy-to-ec2.sh YOUR_EC2_IP YOUR_FRONTEND_URL
```

Or manually:

```bash
# On EC2
docker stop notification-platform-backend
docker rm notification-platform-backend
docker rmi notification-backend:latest

# Then repeat the deployment steps
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs notification-platform-backend

# Check if port is already in use
sudo netstat -tulpn | grep 8001
```

### CORS Errors

1. Check ALLOWED_ORIGINS environment variable:
```bash
docker exec notification-platform-backend env | grep ALLOWED_ORIGINS
```

2. Verify the frontend URL matches exactly (including protocol)

3. Check the root endpoint to see configured origins:
```bash
curl http://YOUR_EC2_IP:8001/
```

### Database Issues

```bash
# Check if data directory exists
ls -la ~/notification-platform-data

# Check database file permissions
ls -la ~/notification-platform-data/app.db

# Access container shell to debug
docker exec -it notification-platform-backend /bin/bash
```

### Port Not Accessible

1. Check EC2 Security Group allows port 8001
2. Check if container is running: `docker ps`
3. Check if port is exposed: `docker port notification-platform-backend`

## Monitoring

### View Real-time Logs

```bash
docker logs -f notification-platform-backend
```

### Check Container Resource Usage

```bash
docker stats notification-platform-backend
```

### Restart Container

```bash
docker restart notification-platform-backend
```

## Backup and Restore

### Backup Database

```bash
# Create backup
cp ~/notification-platform-data/app.db ~/notification-platform-data/app.db.backup-$(date +%Y%m%d)

# Or use Docker
docker exec notification-platform-backend sqlite3 /app/data/app.db ".backup /app/data/backup.db"
```

### Restore Database

```bash
# Stop container
docker stop notification-platform-backend

# Restore backup
cp ~/notification-platform-data/app.db.backup-YYYYMMDD ~/notification-platform-data/app.db

# Start container
docker start notification-platform-backend
```

## Production Recommendations

1. **Use Elastic IP**: Assign an Elastic IP to your EC2 instance for a static IP address
2. **Enable HTTPS**: Use a reverse proxy (nginx) with SSL certificate
3. **Set up CloudWatch**: Monitor logs and metrics
4. **Regular Backups**: Automate database backups
5. **Use Secrets Manager**: Store sensitive environment variables in AWS Secrets Manager
6. **Restrict CORS**: Set specific allowed origins, not "*"
7. **Set up Auto-scaling**: Use Auto Scaling Groups for high availability
8. **Use RDS**: Consider using RDS instead of SQLite for production

## Next Steps

After deploying the backend:

1. Update frontend `.env.local` with the EC2 backend URL
2. Rebuild and redeploy the frontend to S3
3. Test the full integration
4. Set up monitoring and alerts

