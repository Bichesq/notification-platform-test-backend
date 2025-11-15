# GitHub Actions Workflows

This directory contains automated CI/CD workflows for the Cloud Heroes Africa project.

## Available Workflows

### 1. Deploy Backend to AWS ECS (`deploy-to-ecs.yml`)

Automates the deployment of the notification-platform-test-backend application to AWS ECS.

#### Triggers
- **Automatic**: Push to `main` branch with changes in:
  - `test-frontend-backend/notification-platform-test-backend/**`
  - `.github/workflows/deploy-to-ecs.yml`
- **Manual**: Via GitHub Actions UI (workflow_dispatch)

#### What it does
1. Checks out the code
2. Configures AWS credentials
3. Logs into Amazon ECR
4. Builds Docker image from the backend application
5. Tags and pushes image to ECR
6. Updates ECS task definition with new image
7. Deploys to ECS service
8. Waits for service stability
9. Verifies deployment and provides summary

#### Required Secrets

Configure these in **Settings → Secrets and variables → Actions**:

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `AWS_ACCESS_KEY_ID` | AWS IAM user access key | ✅ Yes |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM user secret key | ✅ Yes |
| `AWS_REGION` | AWS region (optional) | ⚠️ Optional (defaults to us-east-1) |

#### Configuration

Edit the workflow file to customize these environment variables:

```yaml
env:
  AWS_REGION: us-east-1                          # Your AWS region
  ECR_REPOSITORY: notification-platform-backend  # ECR repository name
  ECS_SERVICE: notification-platform-service     # ECS service name
  ECS_CLUSTER: notification-platform-cluster     # ECS cluster name
  ECS_TASK_DEFINITION: notification-platform-task # Task definition family
  CONTAINER_NAME: notification-platform-backend  # Container name in task def
  APP_PORT: 8001                                 # Application port
```

#### Prerequisites

Before using this workflow, ensure you have:

1. **AWS Resources Created**:
   - ECR repository
   - ECS cluster
   - ECS task definition
   - ECS service
   - CloudWatch log group
   - IAM role for task execution

2. **GitHub Secrets Configured**:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY

3. **IAM Permissions**:
   - ECR: Push/pull images
   - ECS: Update services and task definitions
   - IAM: PassRole for task execution role

#### Quick Setup

Run the setup script to create all required AWS resources:

```bash
cd test-frontend-backend/notification-platform-test-backend
chmod +x setup-ecs-infrastructure.sh
./setup-ecs-infrastructure.sh us-east-1
```

Then follow the instructions in the script output to:
1. Push initial Docker image to ECR
2. Create ECS service
3. Set up GitHub Actions IAM user
4. Configure GitHub Secrets

#### Manual Deployment

To manually trigger a deployment:

1. Go to **Actions** tab in GitHub
2. Select **Deploy Backend to AWS ECS**
3. Click **Run workflow**
4. Select branch (usually `main`)
5. Click **Run workflow** button

#### Monitoring Deployment

**In GitHub Actions:**
- View real-time logs in the Actions tab
- Check deployment summary at the end of the workflow
- Review any errors in failed steps

**In AWS Console:**
- **ECR**: Verify new image was pushed
- **ECS**: Check service status and running tasks
- **CloudWatch**: View application logs

#### Troubleshooting

**Workflow fails at "Login to Amazon ECR":**
- Verify AWS credentials in GitHub Secrets
- Check IAM user has ECR permissions

**Workflow fails at "Build, tag, and push image":**
- Check Dockerfile syntax
- Verify all required files exist in backend directory

**Workflow fails at "Download current task definition":**
- Ensure task definition exists in AWS
- Verify task definition name matches workflow config

**Workflow fails at "Deploy Amazon ECS task definition":**
- Check ECS service exists
- Verify service name and cluster name are correct
- Check IAM permissions for ECS

**Service doesn't update:**
- Force new deployment from AWS Console
- Check CloudWatch logs for container errors
- Verify security group allows traffic on port 8001

#### Cost Considerations

Running this workflow incurs costs for:
- **GitHub Actions**: Free for public repos, limited minutes for private repos
- **AWS ECS**: Fargate compute charges (~$8-15/month for small workload)
- **AWS ECR**: Storage charges (~$0.10/GB/month)
- **AWS CloudWatch**: Log storage and ingestion

#### Best Practices

1. **Test locally first**: Build and test Docker image locally before pushing
2. **Use staging environment**: Test deployments in staging before production
3. **Monitor costs**: Set up AWS billing alerts
4. **Review logs**: Check CloudWatch logs after each deployment
5. **Rollback plan**: Know how to rollback to previous version if needed
6. **Security**: Rotate AWS credentials regularly
7. **Notifications**: Set up Slack/email notifications for deployment status

#### Rollback Procedure

If a deployment fails or causes issues:

1. **Via GitHub Actions**:
   - Go to Actions tab
   - Find the last successful deployment
   - Click "Re-run jobs"

2. **Via AWS Console**:
   - Go to ECS → Clusters → Your Cluster → Your Service
   - Click "Update"
   - Select previous task definition revision
   - Click "Update Service"

3. **Via AWS CLI**:
   ```bash
   aws ecs update-service \
     --cluster notification-platform-cluster \
     --service notification-platform-service \
     --task-definition notification-platform-task:PREVIOUS_REVISION
   ```

#### Additional Resources

- **Setup Guide**: `test-frontend-backend/ECS_DEPLOYMENT_SETUP.md`
- **Quick Start**: `test-frontend-backend/ECS_QUICK_START.md`
- **EC2 vs ECS**: `test-frontend-backend/EC2_VS_ECS_COMPARISON.md`
- **AWS ECS Docs**: https://docs.aws.amazon.com/ecs/
- **GitHub Actions Docs**: https://docs.github.com/en/actions

## Future Workflows

Potential workflows to add:

- **Frontend Deployment**: Deploy Next.js frontend to S3
- **Run Tests**: Automated testing on pull requests
- **Security Scanning**: Scan Docker images for vulnerabilities
- **Database Migrations**: Run database migrations before deployment
- **Backup**: Automated database backups

## Support

For issues with workflows:
1. Check workflow logs in GitHub Actions
2. Review AWS CloudWatch logs
3. Verify all prerequisites are met
4. Check AWS service status
5. Review documentation in `test-frontend-backend/` directory

trigger finger again