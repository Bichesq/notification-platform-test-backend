# Deploy Backend Without Local Docker

If you don't have Docker installed on your local Windows machine, you can deploy the backend directly on your EC2 instance.

## Prerequisites

- EC2 instance running (Ubuntu or Amazon Linux)
- SSH access to EC2 instance
- Docker installed on EC2 instance

## Method 1: Upload Code and Build on EC2 (Recommended)

### Step 1: Upload Backend Code to EC2

**Option A: Using SCP (Git Bash or WSL)**

```bash
# Navigate to the backend directory
cd test-frontend-backend/notification-platform-test-backend

# Upload all files to EC2
scp -i /path/to/your-key.pem -r . ubuntu@YOUR_EC2_IP:~/backend/
```

**Option B: Using Git (if your code is in a repository)**

```bash
# SSH into EC2
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_IP

# Clone the repository
git clone YOUR_REPO_URL
cd YOUR_REPO/test-frontend-backend/notification-platform-test-backend
```

**Option C: Using WinSCP (Windows GUI)**

1. Download WinSCP: https://winscp.net/
2. Connect to your EC2 instance using your .pem key
3. Upload the `notification-platform-test-backend` folder

### Step 2: Install Docker on EC2 (if not already installed)

SSH into your EC2 instance:

```bash
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_IP
```

**For Ubuntu:**
```bash
# Update package index
sudo apt-get update

# Install Docker
sudo apt-get install -y docker.io

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to docker group
sudo usermod -aG docker $USER

# Log out and log back in for group changes to take effect
exit
```

**For Amazon Linux 2:**
```bash
# Update packages
sudo yum update -y

# Install Docker
sudo yum install docker -y

# Start Docker service
sudo service docker start

# Add your user to docker group
sudo usermod -a -G docker ec2-user

# Log out and log back in
exit
```

### Step 3: Deploy on EC2

SSH back into EC2:

```bash
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_IP
```

Navigate to the backend directory:

```bash
cd ~/backend  # or wherever you uploaded the code
```

Make the deployment script executable and run it:

```bash
chmod +x deploy-on-ec2.sh

# Deploy with your S3 bucket URL
./deploy-on-ec2.sh https://your-bucket.s3.amazonaws.com

# Or for development (allow all origins)
./deploy-on-ec2.sh
```

### Step 4: Verify Deployment

```bash
# Check container status
docker ps

# Check logs
docker logs notification-platform-backend

# Test health endpoint
curl http://localhost:8001/health

# Test from your local machine (replace with your EC2 IP)
curl http://YOUR_EC2_IP:8001/health
```

## Method 2: Manual Deployment on EC2

If you prefer to run commands manually:

### Step 1: SSH into EC2

```bash
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_IP
```

### Step 2: Upload Code

Use one of the methods from Method 1, Step 1.

### Step 3: Build and Run Container

```bash
# Navigate to backend directory
cd ~/backend

# Create data directory
mkdir -p ~/notification-platform-data

# Build Docker image
docker build -t notification-backend:latest .

# Stop old container (if exists)
docker stop notification-platform-backend 2>/dev/null || true
docker rm notification-platform-backend 2>/dev/null || true

# Run container
docker run -d \
  --name notification-platform-backend \
  --restart unless-stopped \
  -p 8001:8001 \
  -v ~/notification-platform-data:/app/data \
  -e DATABASE_URL=sqlite:///./data/app.db \
  -e ALLOWED_ORIGINS="https://your-bucket.s3.amazonaws.com" \
  notification-backend:latest

# Check status
docker ps

# View logs
docker logs notification-platform-backend

# Test health
curl http://localhost:8001/health
```

## Method 3: Using PowerShell/CMD (Windows)

If you want to upload files from Windows without Git Bash:

### Step 1: Install OpenSSH (if not already installed)

Windows 10/11 usually has OpenSSH built-in. If not:

```powershell
# Run as Administrator
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

### Step 2: Upload Files Using SCP

```powershell
# Navigate to backend directory
cd "C:\Users\biche\Cloud Heroes Africa\test-frontend-backend\notification-platform-test-backend"

# Upload files (replace paths with your actual paths)
scp -i C:\path\to\your-key.pem -r * ubuntu@YOUR_EC2_IP:~/backend/
```

### Step 3: SSH and Deploy

```powershell
# SSH into EC2
ssh -i C:\path\to\your-key.pem ubuntu@YOUR_EC2_IP

# Then follow Method 1, Step 3
```

## Troubleshooting

### Permission Denied (publickey)

Make sure your .pem key has correct permissions:

**Git Bash/WSL:**
```bash
chmod 400 /path/to/your-key.pem
```

**PowerShell:**
```powershell
icacls "C:\path\to\your-key.pem" /inheritance:r
icacls "C:\path\to\your-key.pem" /grant:r "%username%:R"
```

### Docker Command Not Found on EC2

Install Docker using the commands in Method 1, Step 2.

### Permission Denied (Docker)

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and log back in
exit
```

### Port 8001 Not Accessible

1. Check EC2 Security Group allows port 8001
2. Check container is running: `docker ps`
3. Check logs: `docker logs notification-platform-backend`

### Container Fails to Start

```bash
# Check logs
docker logs notification-platform-backend

# Check if port is already in use
sudo netstat -tulpn | grep 8001

# Try running without -d to see errors
docker run --rm -p 8001:8001 notification-backend:latest
```

## Quick Reference

### Upload Code to EC2

```bash
# From your local machine (Git Bash)
cd test-frontend-backend/notification-platform-test-backend
scp -i /path/to/key.pem -r . ubuntu@EC2_IP:~/backend/
```

### Deploy on EC2

```bash
# SSH into EC2
ssh -i /path/to/key.pem ubuntu@EC2_IP

# Navigate and deploy
cd ~/backend
chmod +x deploy-on-ec2.sh
./deploy-on-ec2.sh https://your-bucket.s3.amazonaws.com
```

### Verify

```bash
# On EC2
curl http://localhost:8001/health

# From local machine
curl http://EC2_IP:8001/health
```

## Next Steps

After successful deployment:

1. ✅ Verify backend is accessible from your local machine
2. ✅ Update frontend `.env.local` with EC2 IP
3. ✅ Rebuild frontend: `npm run build`
4. ✅ Deploy frontend to S3: `aws s3 sync out/ s3://bucket --delete`
5. ✅ Test the integration

## Alternative: Use AWS Systems Manager Session Manager

If you have trouble with SSH, you can use AWS Systems Manager:

1. Go to AWS Console → EC2 → Instances
2. Select your instance
3. Click "Connect" → "Session Manager"
4. Click "Connect"

This gives you a browser-based terminal without needing SSH keys!

## Summary

**Easiest Method:**
1. Upload code to EC2 using SCP or WinSCP
2. SSH into EC2
3. Run `./deploy-on-ec2.sh YOUR_S3_URL`
4. Done! ✅

No need for Docker on your local Windows machine!

