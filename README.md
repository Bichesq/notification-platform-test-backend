# Notification Platform Backend

FastAPI-based backend service for managing applications and API keys.

## Features

- ✅ Application management (CRUD operations)
- ✅ API key generation and management
- ✅ SQLite database (easily switchable to PostgreSQL)
- ✅ CORS support for S3-hosted frontend
- ✅ Docker containerization
- ✅ Health check endpoints
- ✅ API key authentication

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python server.py
```

Server will start at `http://localhost:8001`

### Docker Development

```bash
# Build image
docker build -t notification-backend .

# Run container
docker run -d \
  --name notification-platform-backend \
  -p 8001:8001 \
  -e ALLOWED_ORIGINS="*" \
  notification-backend:latest
```

### Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Deployment

### Deploy to EC2

**Quick Deploy:**
```bash
chmod +x deploy-to-ec2.sh
./deploy-to-ec2.sh <EC2_IP> <FRONTEND_URL>
```

**Example:**
```bash
./deploy-to-ec2.sh 54.87.39.36 https://my-bucket.s3.amazonaws.com
```

**Manual Deploy:**
See [EC2_DEPLOYMENT.md](EC2_DEPLOYMENT.md) for detailed instructions.

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# Database
DATABASE_URL=sqlite:///./app.db

# CORS - comma-separated origins
ALLOWED_ORIGINS=https://your-bucket.s3.amazonaws.com,https://your-domain.com

# Application
APP_PORT=8001
APP_HOST=0.0.0.0
```

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
curl http://localhost:8001/apps

# Create application
curl -X POST http://localhost:8001/app \
  -H "Content-Type: application/json" \
  -d '{"name":"Test App","email":"test@example.com","domain":"example.com"}'
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

### SQLite (Default)

Data stored in `app.db` file (or `/app/data/app.db` in Docker).

### PostgreSQL (Production)

Update `DATABASE_URL`:
```bash
DATABASE_URL=postgresql://user:password@host:5432/dbname
```

### Backup

```bash
# SQLite backup
cp app.db app.db.backup

# Docker volume backup
docker exec notification-platform-backend sqlite3 /app/data/app.db ".backup /app/data/backup.db"
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
# Access container shell
docker exec -it notification-platform-backend /bin/bash

# Check database file
ls -la /app/data/app.db
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

### Database Migrations

For schema changes:
1. Update SQLAlchemy models in `server.py`
2. Delete `app.db` (development only)
3. Restart server to recreate tables
4. For production, use Alembic for migrations

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
- [ ] Use strong database passwords
- [ ] Enable CloudWatch logging
- [ ] Set up automated backups
- [ ] Use Secrets Manager for sensitive data
- [ ] Restrict EC2 Security Group
- [ ] Enable VPC security

## Performance

### Optimization Tips

1. Use PostgreSQL for production
2. Enable database connection pooling
3. Add caching layer (Redis)
4. Use CDN for static assets
5. Enable gzip compression
6. Optimize database queries

### Scaling

1. Use Application Load Balancer
2. Deploy multiple EC2 instances
3. Use Auto Scaling Groups
4. Implement health checks
5. Use RDS with read replicas

## License

[Your License Here]

## Support

For issues or questions:
- Check [EC2_DEPLOYMENT.md](EC2_DEPLOYMENT.md) 
- Check API documentation at `/docs`

## Related Documentation

- [EC2 Deployment Guide](EC2_DEPLOYMENT.md)
- [Integration Guide](../../INTEGRATION_GUIDE.md)
- [Quick Reference](../../QUICK_DEPLOYMENT_REFERENCE.md)

