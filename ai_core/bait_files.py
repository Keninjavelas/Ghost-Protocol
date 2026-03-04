"""
ai_core/bait_files.py
Credential theft trap definitions and realistic corporate filesystem.

High-value bait files guaranteed to appear in every session.
Accessing these files triggers credential access detection and threat escalation.

Includes:
- Directory structure resembling a corporate Linux server
- Configuration files (nginx, deployment scripts)
- Business data (payroll, employee records)
- Cloud infrastructure artifacts (AWS, Kubernetes, Terraform)
- Credential storage mistakes (passwords, keys, env files)

SECURITY NOTE:
All credentials in this file use the HP_DEMO_ prefix to ensure they:
• Never trigger GitHub secret scanning or leak detection tools
• Cannot be accidentally used against real services
• Are clearly identifiable as honeypot/demonstration credentials
• Enable reliable credential exfiltration detection
"""
from __future__ import annotations

from typing import Any
from ai_core import demo_credentials as hp_creds

# ── Bait File Definitions ──────────────────────────────────────────────────────

BAIT_FILES: dict[str, dict[str, Any]] = {
    # ═══════════════════════════════════════════════════════════════════════════
    # DIRECTORY STRUCTURE
    # ═══════════════════════════════════════════════════════════════════════════
    "/root": {
        "content_hint": "Root user home directory",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/home/admin": {
        "content_hint": "Administrator user directory",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/home/devops": {
        "content_hint": "DevOps engineer user directory",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/etc/nginx": {
        "content_hint": "Nginx web server configuration",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/etc/nginx/sites-enabled": {
        "content_hint": "Active nginx site configurations",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/var/backups": {
        "content_hint": "System and database backups",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/opt/company": {
        "content_hint": "Company internal applications and data",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/opt/company/finance": {
        "content_hint": "Financial department files",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/opt/company/hr": {
        "content_hint": "Human resources records",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    "/opt/company/devops": {
        "content_hint": "DevOps team scripts and configurations",
        "is_directory": True,
        "is_bait": False,
        "is_sensitive": False,
    },
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CLOUD INFRASTRUCTURE CREDENTIALS
    # ═══════════════════════════════════════════════════════════════════════════
    "/root/.aws/credentials": {
        "content_hint": "AWS IAM credentials",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": f"""[default]
aws_access_key_id = {hp_creds.generate_aws_access_key()}
aws_secret_access_key = {hp_creds.generate_aws_secret_key()}
region = us-east-1

[production]
aws_access_key_id = {hp_creds.generate_aws_access_key()}
aws_secret_access_key = {hp_creds.generate_aws_secret_key()}
region = us-west-2
""",
    },
    "/home/admin/passwords.txt": {
        "content_hint": "Plain text password list",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": f"""# Production Server Credentials
# DO NOT SHARE EXTERNALLY

admin:{hp_creds.generate_user_password('admin')}
backup_user:{hp_creds.generate_user_password('backup')}
database_admin:{hp_creds.generate_db_password('MYSQL')}
ftp_service:{hp_creds.generate_user_password('ftp')}
monitoring_agent:{hp_creds.generate_user_password('monitoring')}
""",
    },
    "/var/backups/db_backup.sql": {
        "content_hint": "MySQL database backup with credentials",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """-- MySQL Database Backup
-- Generated: 2026-03-01 08:00:00
-- Database: production_users

CREATE DATABASE IF NOT EXISTS production_users;
USE production_users;

-- Admin credentials table
CREATE TABLE admin_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO admin_users (username, password_hash, email) VALUES
('admin', '{hp_creds.generate_password_hash()}', 'admin@company.local'),
('root', '{hp_creds.generate_password_hash()}', 'root@company.local'),
('sysadmin', '{hp_creds.generate_password_hash()}', 'sysadmin@company.local');

-- API Keys table
CREATE TABLE api_keys (
  id INT PRIMARY KEY AUTO_INCREMENT,
  service_name VARCHAR(100),
  api_key VARCHAR(255),
  secret_key VARCHAR(255)
);

INSERT INTO api_keys (service_name, api_key, secret_key) VALUES
('stripe', '{hp_creds.generate_api_key("STRIPE")}', '{hp_creds.generate_webhook_secret()}'),
('sendgrid', '{hp_creds.generate_api_key("SENDGRID")}', NULL),
('twilio', '{hp_creds.generate_api_key("TWILIO")}', '{hp_creds.generate_access_token("TWILIO")}');

-- Connection string in comments (bad practice!)
-- Production DB: {hp_creds.generate_connection_string("mysql")}
""",
    },
    "/var/backups/customer_db.sql": {
        "content_hint": "Customer database export with PII",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """-- Demo database export
-- Customer Database Backup
-- Generated: 2026-03-04 10:30:00
-- WARNING: Contains PII - Handle with care

USE customer_data;

-- Customer table with sensitive PII
CREATE TABLE customers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255),
  credit_card_last4 VARCHAR(4),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO customers (id, email, password_hash, full_name, credit_card_last4) VALUES
(1, 'john.doe@example.com', 'hashed_pw_1', 'John Doe', '4532'),
(2, 'alice@company.com', 'hashed_pw_2', 'Alice Smith', '8765'),
(3, 'bob@financecorp.com', 'hashed_pw_3', 'Bob Johnson', '2198'),
(4, 'carol.williams@enterprise.net', 'hashed_pw_4', 'Carol Williams', '6543'),
(5, 'dave.miller@bigcorp.com', 'hashed_pw_5', 'Dave Miller', '9876');

-- Payment methods table
CREATE TABLE payment_methods (
  customer_id INT,
  card_type VARCHAR(50),
  last_four VARCHAR(4),
  expiry_date VARCHAR(7),
  billing_zip VARCHAR(10)
);

INSERT INTO payment_methods VALUES
(1, 'Visa', '4532', '12/2027', '94105'),
(2, 'MasterCard', '8765', '06/2026', '10001'),
(3, 'Amex', '2198', '03/2028', '60601'),
(4, 'Visa', '6543', '09/2027', '98101'),
(5, 'Discover', '9876', '11/2025', '33101');

-- Admin access credentials (PRODUCTION)
-- Database: {hp_creds.generate_connection_string("mysql")}
-- Redis Cache: {hp_creds.generate_connection_string("redis")}
""",
    },
    "/etc/shadow_backup": {
        "content_hint": "Backup copy of /etc/shadow with password hashes",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1003.008",  # OS Credential Dumping: /etc/passwd and /etc/shadow
        "content": """root:$6$rounds=656000$ExampleSaltString$ExampleHashA1B2C3D4E5F6G7H8I9J0K:19757:0:99999:7:::
daemon:*:19757:0:99999:7:::
bin:*:19757:0:99999:7:::
sys:*:19757:0:99999:7:::
admin:$6$rounds=656000$AnotherSaltValue$AnotherHashZ9Y8X7W6V5U4T3S2R1Q:19757:0:99999:7:::
backup:$6$rounds=656000$BackupUserSalt$BackupHashM1N2O3P4Q5R6S7T8U9V0W:19757:0:99999:7:::
sysadmin:$6$rounds=656000$SysAdminSalt$SysAdminHash0A1B2C3D4E5F:19757:0:99999:7:::
mysql:!:19757:0:99999:7:::
www-data:*:19757:0:99999:7:::
""",
    },
    "/root/.ssh/id_rsa": {
        "content_hint": "Private SSH key for root user",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.004",  # Unsecured Credentials: Private Keys
        "content": hp_creds.generate_ssh_private_key_placeholder(),
    },
    "/home/admin/.env": {
        "content_hint": "Environment variables with secrets",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": f"""# Production Environment Variables
# WARNING: Do not commit to version control

DATABASE_URL={hp_creds.generate_connection_string("postgresql")}
REDIS_URL={hp_creds.generate_connection_string("redis")}

# API Keys
STRIPE_SECRET_KEY={hp_creds.generate_api_key("STRIPE")}
SENDGRID_API_KEY={hp_creds.generate_api_key("SENDGRID")}
JWT_SECRET={hp_creds.generate_jwt_secret()}

# AWS Credentials
AWS_ACCESS_KEY_ID={hp_creds.generate_aws_access_key()}
AWS_SECRET_ACCESS_KEY={hp_creds.generate_aws_secret_key()}

# Third-party integrations
SLACK_WEBHOOK_URL={hp_creds.generate_slack_webhook_url()}
GITHUB_PERSONAL_TOKEN={hp_creds.generate_access_token("GITHUB")}
""",
    },
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEM CONFIGURATION FILES
    # ═══════════════════════════════════════════════════════════════════════════
    "/etc/nginx/nginx.conf": {
        "content_hint": "Nginx reverse proxy configuration",
        "is_bait": True,
        "is_sensitive": False,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
""",
    },
    "/etc/nginx/sites-enabled/api.conf": {
        "content_hint": "Internal API routing configuration",
        "is_bait": True,
        "is_sensitive": False,
        "mitre_technique": "T1082",  # System Information Discovery
        "content": """# Internal API Gateway Configuration
# Production environment

upstream api_backend {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}

upstream internal_services {
    server 10.0.2.20:5000;
    server 10.0.2.21:5000;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name api.company.internal;
    
    ssl_certificate /etc/nginx/ssl/company.crt;
    ssl_certificate_key /etc/nginx/ssl/company.key;
    
    # API endpoints
    location /api/v1/ {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Internal authentication
        # auth_basic "Restricted Access";
        # auth_basic_user_file /etc/nginx/.htpasswd;
    }
    
    # Admin panel (restricted)
    location /admin/ {
        proxy_pass http://internal_services;
        allow 10.0.0.0/8;
        deny all;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}

# Database admin interface (DEPRECATED - should be removed)
server {
    listen 8888;
    server_name db-admin.company.internal;
    
    location / {
        proxy_pass http://10.0.3.100:8080;
        # TODO: Add authentication before production!
    }
}
""",
    },
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DEPLOYMENT & AUTOMATION SCRIPTS
    # ═══════════════════════════════════════════════════════════════════════════
    "/opt/company/devops/deploy.sh": {
        "content_hint": "Production deployment automation script",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": f"""#!/bin/bash
# Production Deployment Script
# Codename: Project Phoenix
# WARNING: Contains production credentials - DO NOT SHARE

set -e

# Environment
ENVIRONMENT="production"
DEPLOY_USER="deploy"
DEPLOY_KEY="/root/.ssh/deploy_key"

# Database credentials (temporary - migrate to vault!)
export DB_HOST="prod-db-01.internal"
export DB_USER="deploy_agent"
export DB_PASS="{hp_creds.generate_db_password('DEPLOY')}"

# Container registry
REGISTRY="registry.company.internal:5000"
REGISTRY_USER="ci-deployer"
REGISTRY_PASS="{hp_creds.generate_registry_password()}"

# Kubernetes cluster
KUBE_CONTEXT="prod-cluster-us-east"
KUBE_NAMESPACE="production"

echo "[+] Starting deployment to $ENVIRONMENT"
echo "[+] Authenticating to container registry..."

echo "$REGISTRY_PASS" | docker login -u "$REGISTRY_USER" --password-stdin $REGISTRY

echo "[+] Pulling latest images..."
docker pull $REGISTRY/api-service:latest
docker pull $REGISTRY/worker-service:latest
docker pull $REGISTRY/frontend:latest

echo "[+] Applying Kubernetes manifests..."
kubectl --context=$KUBE_CONTEXT apply -f k8s/production/

echo "[+] Updating database schema..."
mysql -h $DB_HOST -u $DB_USER -p$DB_PASS production_db < migrations/latest.sql

echo "[+] Restarting services..."
kubectl --context=$KUBE_CONTEXT rollout restart deployment/api-service -n $KUBE_NAMESPACE
kubectl --context=$KUBE_CONTEXT rollout restart deployment/worker-service -n $KUBE_NAMESPACE

echo "[+] Deployment complete!"
echo "[+] Triggering Slack notification..."
curl -X POST {hp_creds.generate_slack_webhook_url()} \
     -H 'Content-Type: application/json' \
     -d '{{"text":"✅ Production deployment successful"}}'

# Backup deployment logs
cp /var/log/deploy.log /var/backups/deploy_$(date +%Y%m%d_%H%M%S).log
""",
    },
    "/home/devops/kubeconfig.yaml": {
        "content_hint": "Kubernetes cluster access configuration",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": """apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJRXhhbXBsZUNlcnQwRFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TkRBeE1EZ3dNREF3TURCYUZ3MHpOREF4TURVd01EQXdNREJhTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUURkRXhhbXBsZURhdGFIZXJl
    server: https://prod-cluster-us-east.company.internal:6443
  name: prod-cluster-us-east
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJQW5vdGhlckV4YW1wbGUwRFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFRwpBMVVFQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TkRBeE1EZ3dNREF3TURCYUZ3MHpOREF4TURVd01EQXdNREJhCk1CVXGFRGFXZXJEZGF0RXhhbXBsZUhlcmU=
    server: https://staging-cluster.company.internal:6443
  name: staging-cluster
contexts:
- context:
    cluster: prod-cluster-us-east
    user: admin-user
    namespace: production
  name: prod-admin
- context:
    cluster: staging-cluster
    user: devops-user
    namespace: staging
  name: staging-deploy
current-context: prod-admin
users:
- name: admin-user
  user:
    client-certificate-data: {hp_creds.generate_certificate_data()}
    client-key-data: {hp_creds.generate_certificate_data()}
- name: devops-user
  user:
    token: {hp_creds.generate_kubeconfig_token()}
""",
    },
    "/home/devops/terraform.tfstate": {
        "content_hint": "Terraform infrastructure state file",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": """{
  "version": 4,
  "terraform_version": "1.7.0",
  "serial": 42,
  "lineage": "8f9a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c",
  "outputs": {
    "database_endpoint": {
      "value": "prod-postgres.cg8x1y2z3a4b.us-east-1.rds.amazonaws.com:5432",
      "type": "string"
    },
    "redis_endpoint": {
      "value": "prod-redis.abcdef.0001.use1.cache.amazonaws.com:6379",
      "type": "string"
    },
    "s3_bucket_name": {
      "value": "company-production-data-2026",
      "type": "string"
    }
  },
  "resources": [
    {
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "production",
      "provider": "provider[\\"registry.terraform.io/hashicorp/aws\\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "identifier": "prod-postgres",
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": "db.r6g.xlarge",
            "allocated_storage": 500,
            "storage_type": "gp3",
            "username": "dbadmin",
            "password": "{hp_creds.generate_db_password('POSTGRES')}",
            "db_name": "production_db",
            "endpoint": "prod-postgres.cg8x1y2z3a4b.us-east-1.rds.amazonaws.com:5432",
            "publicly_accessible": false,
            "vpc_security_group_ids": ["sg-0a1b2c3d4e5f6g7h8"],
            "backup_retention_period": 30,
            "multi_az": true
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_elasticache_cluster",
      "name": "redis_cache",
      "provider": "provider[\\"registry.terraform.io/hashicorp/aws\\"]",
      "instances": [
        {
          "attributes": {
            "cluster_id": "prod-redis",
            "engine": "redis",
            "node_type": "cache.r6g.large",
            "num_cache_nodes": 3,
            "port": 6379,
            "auth_token": "{hp_creds.generate_db_password('REDIS')}"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data_storage",
      "instances": [
        {
          "attributes": {
            "bucket": "company-production-data-2026",
            "acl": "private",
            "versioning": {
              "enabled": true
            },
            "tags": {
              "Environment": "Production",
              "ManagedBy": "Terraform",
              "CostCenter": "Engineering"
            }
          }
        }
      ]
    }
  ]
}
""",
    },
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SENSITIVE BUSINESS DATA
    # ═══════════════════════════════════════════════════════════════════════════
    "/opt/company/finance/payroll_2024.csv": {
        "content_hint": "Employee salary and compensation data",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """employee_id,name,email,salary,bonus,department,ssn_last4
1001,Alice Johnson,alice.johnson@company.internal,95000,8500,Engineering,6789
1002,Mark Evans,mark.evans@company.internal,88000,7000,Finance,4532
1003,Daniel Smith,daniel.smith@company.internal,102000,12000,Engineering,8765
1004,Sarah Williams,sarah.williams@company.internal,78000,5000,HR,2198
1005,Robert Brown,robert.brown@company.internal,115000,15000,Engineering,3456
1006,Jennifer Davis,jennifer.davis@company.internal,92000,9000,Product,7890
1007,Michael Miller,michael.miller@company.internal,125000,20000,Executive,1234
1008,Lisa Anderson,lisa.anderson@company.internal,85000,6500,Marketing,5678
1009,David Wilson,david.wilson@company.internal,98000,10000,Engineering,9012
1010,Jessica Taylor,jessica.taylor@company.internal,81000,6000,Sales,3456
""",
    },
    "/opt/company/hr/employees.csv": {
        "content_hint": "Employee directory with contact information",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """employee_id,name,email,phone,role,manager,start_date,status
1001,Alice Johnson,alice.johnson@company.internal,+1-555-0101,Senior Engineer,Michael Miller,2022-03-15,Active
1002,Mark Evans,mark.evans@company.internal,+1-555-0102,Financial Analyst,Jennifer Davis,2021-07-20,Active
1003,Daniel Smith,daniel.smith@company.internal,+1-555-0103,Lead Engineer,Michael Miller,2020-01-10,Active
1004,Sarah Williams,sarah.williams@company.internal,+1-555-0104,HR Manager,Michael Miller,2021-11-05,Active
1005,Robert Brown,robert.brown@company.internal,+1-555-0105,Principal Engineer,Michael Miller,2019-05-22,Active
1006,Jennifer Davis,jennifer.davis@company.internal,+1-555-0106,Product Director,Michael Miller,2020-08-18,Active
1007,Michael Miller,michael.miller@company.internal,+1-555-0107,CTO,CEO,2018-02-01,Active
1008,Lisa Anderson,lisa.anderson@company.internal,+1-555-0108,Marketing Lead,Jennifer Davis,2022-09-12,Active
1009,David Wilson,david.wilson@company.internal,+1-555-0109,DevOps Engineer,Daniel Smith,2023-01-30,Active
1010,Jessica Taylor,jessica.taylor@company.internal,+1-555-0110,Sales Manager,Jennifer Davis,2021-04-07,Active
1011,Thomas Moore,thomas.moore@company.internal,+1-555-0111,Security Analyst,Daniel Smith,2023-06-15,Terminated
""",
    },
    "/opt/company/hr/performance_reviews_2024.txt": {
        "content_hint": "Employee performance review notes",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1005",  # Data from Local System
        "content": """CONFIDENTIAL - 2024 Q1 Performance Reviews
===================================================

Employee: Alice Johnson (1001)
Rating: Exceeds Expectations (4/5)
Notes: Strong technical leadership. Led migration to Kubernetes. Recommended for promotion.
Compensation Adjustment: +8% salary increase approved.

Employee: Mark Evans (1002)
Rating: Meets Expectations (3/5)
Notes: Solid performance. Needs improvement on cross-team communication.
Compensation Adjustment: +3% salary increase.

Employee: Daniel Smith (1003)
Rating: Outstanding (5/5)
Notes: Exceptional architect. Designed new microservices platform. Key retention target.
Compensation Adjustment: +12% salary increase + retention bonus approved.

Employee: Thomas Moore (1011)
Rating: Below Expectations (2/5)
Notes: Multiple security policy violations. Unauthorized access to production systems.
Status: Performance improvement plan initiated. Terminated 2024-07-15.
""",
    },
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DOCUMENTATION & INTERNAL NOTES
    # ═══════════════════════════════════════════════════════════════════════════
    "/opt/company/README.md": {
        "content_hint": "Company internal systems documentation",
        "is_bait": True,
        "is_sensitive": False,
        "mitre_technique": "T1082",  # System Information Discovery
        "content": """# Company Internal Systems Documentation

## Overview
This server hosts critical production infrastructure for our SaaS platform.

## Services Running
- **Nginx** - Reverse proxy and API gateway
- **Internal API** - Backend services (ports 8080-8082)
- **Database** - PostgreSQL production instance
- **Redis** - Session cache and job queue
- **Monitoring** - Prometheus + Grafana

## Directory Structure
- `/opt/company/finance/` - Financial reports and payroll data
- `/opt/company/hr/` - Employee records and performance data
- `/opt/company/devops/` - Deployment scripts and infrastructure code
- `/var/backups/` - Database backups (daily at 2 AM UTC)

## Access Control
Production access requires:
1. VPN connection to 10.0.0.0/8 network
2. SSH key authentication (passwords disabled)
3. AWS IAM role with MFA enabled
4. Kubernetes RBAC permissions

## Emergency Contacts
- On-Call Engineer: oncall@company.internal
- Security Team: security@company.internal  
- Infrastructure Lead: daniel.smith@company.internal

## Important Notes
⚠️ All production credentials are stored in AWS Secrets Manager  
⚠️ Database backups contain PII - handle according to GDPR/CCPA  
⚠️ This server is monitored 24/7 - unauthorized access is logged

Last Updated: 2026-03-01
""",
    },
    "/opt/company/devops/DEPLOYMENT.md": {
        "content_hint": "Production deployment runbook",
        "is_bait": True,
        "is_sensitive": False,
        "mitre_technique": "T1082",  # System Information Discovery
        "content": """# Production Deployment Runbook

## Prerequisites
- AWS CLI configured with production credentials
- kubectl with prod-cluster context
- Docker access to registry.company.internal:5000
- VPN connection active

## Standard Deployment Process

### 1. Pre-deployment Checklist
```bash
# Verify cluster health
kubectl --context=prod-cluster-us-east get nodes
kubectl --context=prod-cluster-us-east get pods -n production

# Check current running version
kubectl --context=prod-cluster-us-east get deployment api-service -n production -o yaml | grep image:

# Backup current database
/opt/company/devops/backup_db.sh
```

### 2. Build and Push Images
```bash
# Build application
docker build -t registry.company.internal:5000/api-service:v1.2.3 .

# Login to registry (credentials in /root/.docker/config.json)
docker login registry.company.internal:5000

# Push image
docker push registry.company.internal:5000/api-service:v1.2.3
```

### 3. Apply Kubernetes Manifests
```bash
# Update deployment
kubectl --context=prod-cluster-us-east set image deployment/api-service \
  api-service=registry.company.internal:5000/api-service:v1.2.3 \
  -n production

# Watch rollout
kubectl --context=prod-cluster-us-east rollout status deployment/api-service -n production
```

### 4. Post-deployment Verification
```bash
# Health check
curl https://api.company.internal/health

# Check logs
kubectl --context=prod-cluster-us-east logs -f deployment/api-service -n production | tail -100

# Monitor error rates in Grafana
# Dashboard: https://grafana.company.internal/d/api-metrics
```

## Rollback Procedure
```bash
# Quick rollback
kubectl --context=prod-cluster-us-east rollout undo deployment/api-service -n production

# Rollback to specific revision
kubectl --context=prod-cluster-us-east rollout undo deployment/api-service -n production --to-revision=42
```

## Database Migrations
```bash
# Connect to production DB
mysql -h prod-postgres.cg8x1y2z3a4b.us-east-1.rds.amazonaws.com \
      -u dbadmin -p \
      production_db

# Apply migrations (stored at /var/backups/migrations/)
mysql production_db < /var/backups/migrations/2026_03_migration.sql
```

## Secrets Management
- AWS credentials: Stored in AWS Secrets Manager
- Kubernetes secrets: Stored in K8s etcd (encrypted at rest)
- Database passwords: Retrieved via AWS RDS IAM authentication
- API keys: Injected via environment variables from sealed-secrets

## Emergency Contacts
- Primary: David Wilson (devops engineer) - +1-555-0109
- Backup: Daniel Smith (lead engineer) - +1-555-0103
- Security: Thomas Moore (security analyst) - +1-555-0111 [TERMINATED]
""",
    },
    "/root/.docker/config.json": {
        "content_hint": "Docker registry authentication",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": """{
  "auths": {
    "registry.company.internal:5000": {
      "auth": "Y2ktZGVwbG95ZXI6UmVnMXN0cnlQQHNzMjAyNg==",
      "email": "devops@company.internal"
    },
    "https://index.docker.io/v1/": {
      "auth": "ZG9ja2VydXNlcjpEb2NrM3JIdWJQQHNzdzByZA==",
      "email": "devops@company.internal"
    }
  },
  "credHelpers": {
    "gcr.io": "gcr",
    "us-east1-docker.pkg.dev": "gcloud"
  },
  "credsStore": "desktop"
}
""",
    },
    "/root/.bash_history": {
        "content_hint": "Root user command history",
        "is_bait": True,
        "is_sensitive": True,
        "mitre_technique": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "content": f"""ls -la
cd /opt/company/
cat /root/.aws/credentials
export AWS_ACCESS_KEY_ID={hp_creds.generate_aws_access_key()}
export AWS_SECRET_ACCESS_KEY={hp_creds.generate_aws_secret_key()}
aws s3 ls
mysql -h prod-postgres.internal -u dbadmin -p{hp_creds.generate_db_password('POSTGRES')} production_db
kubectl --context=prod-cluster-us-east get pods -n production
docker login registry.company.internal:5000 -u ci-deployer -p {hp_creds.generate_registry_password()}
cat /var/backups/customer_db.sql
grep -r "password" /opt/company/
cat /home/admin/.env
ssh -i /root/.ssh/id_rsa admin@10.0.1.10
cat /etc/shadow_backup
./opt/company/devops/deploy.sh
tail -f /var/log/nginx/access.log
cat /opt/company/finance/payroll_2024.csv
history | grep password | tee /tmp/leaked_commands.txt
rm /tmp/leaked_commands.txt
""",
    },
    "/var/log/deployment.log": {
        "content_hint": "Recent deployment activity logs",
        "is_bait": True,
        "is_sensitive": False,
        "mitre_technique": "T1082",  # System Information Discovery
        "content": """[2026-03-04 08:15:22] INFO: Deployment initiated by devops@10.0.2.50
[2026-03-04 08:15:23] INFO: Authenticating to container registry registry.company.internal:5000
[2026-03-04 08:15:24] INFO: Pulling image: registry.company.internal:5000/api-service:v1.2.15
[2026-03-04 08:15:45] INFO: Image pulled successfully
[2026-03-04 08:15:46] INFO: Applying Kubernetes manifests to prod-cluster-us-east
[2026-03-04 08:15:47] INFO: Updated deployment: api-service (production namespace)
[2026-03-04 08:15:48] INFO: Rollout status: 1/3 replicas updated
[2026-03-04 08:16:15] INFO: Rollout status: 2/3 replicas updated
[2026-03-04 08:16:42] INFO: Rollout status: 3/3 replicas updated
[2026-03-04 08:16:43] INFO: Deployment successful
[2026-03-04 08:16:44] INFO: Running health checks...
[2026-03-04 08:16:45] INFO: Health check passed: https://api.company.internal/health (200 OK)
[2026-03-04 08:16:46] INFO: Sending Slack notification to #deployments channel
[2026-03-04 08:16:47] INFO: Deployment completed successfully in 2m25s
[2026-03-04 08:30:15] ERROR: Unauthorized access attempt detected from 192.168.100.45
[2026-03-04 08:30:16] WARN: Failed authentication for user 'thomas.moore' - account terminated
[2026-03-04 08:30:17] INFO: Security alert triggered - notifying security@company.internal
""",
    },
}


def get_all_bait_files() -> dict[str, dict[str, Any]]:
    """Return all bait file definitions."""
    return BAIT_FILES.copy()


def is_directory(file_path: str) -> bool:
    """Check if a path is marked as a directory."""
    return BAIT_FILES.get(file_path, {}).get("is_directory", False)


def is_sensitive_file(file_path: str) -> bool:
    """Check if a file path is marked as sensitive bait."""
    return BAIT_FILES.get(file_path, {}).get("is_sensitive", False)


def get_bait_content(file_path: str) -> str | None:
    """Get the realistic content for a bait file."""
    return BAIT_FILES.get(file_path, {}).get("content")


def get_mitre_technique_for_file(file_path: str) -> str | None:
    """Get the MITRE technique associated with accessing this file."""
    return BAIT_FILES.get(file_path, {}).get("mitre_technique")


def get_files_in_directory(directory_path: str) -> list[tuple[str, dict[str, Any]]]:
    """
    Get all files and subdirectories in a specific directory.
    
    Returns list of (filename, metadata) tuples for files directly in this directory.
    Does not include nested subdirectories' contents.
    
    Example:
        get_files_in_directory("/root") -> [
            (".aws", {"is_directory": True, ...}),
            (".ssh", {"is_directory": True, ...}),
            (".bash_history", {"is_sensitive": True, ...}),
        ]
    """
    # Normalize directory path
    dir_path = directory_path.rstrip("/")
    if not dir_path:
        dir_path = "/"
    
    results = []
    for full_path, metadata in BAIT_FILES.items():
        # Skip the directory itself
        if full_path == dir_path:
            continue
        
        # Check if this path is directly under the target directory
        if full_path.startswith(dir_path + "/"):
            # Get the relative path from the directory
            relative = full_path[len(dir_path) + 1:]
            
            # Only include direct children (no slashes in relative path)
            if "/" not in relative:
                # Extract just the filename/dirname
                results.append((relative, metadata))
            elif "/" in relative:
                # This is a nested path - include the immediate subdirectory
                subdir_name = relative.split("/")[0]
                subdir_path = f"{dir_path}/{subdir_name}"
                
                # Add subdirectory if not already in results
                if subdir_path in BAIT_FILES and not any(r[0] == subdir_name for r in results):
                    results.append((subdir_name, BAIT_FILES[subdir_path]))
    
    return results


def format_directory_listing(directory_path: str, long_format: bool = False) -> str:
    """
    Generate a realistic ls output for a directory.
    
    Args:
        directory_path: The directory to list
        long_format: If True, generate ls -la style output with permissions and dates
    
    Returns:
        Formatted directory listing string
    """
    files = get_files_in_directory(directory_path)
    
    if not files:
        return ""
    
    if long_format:
        # Generate ls -la style output
        lines = []
        for filename, metadata in sorted(files):
            is_dir = metadata.get("is_directory", False)
            is_sensitive = metadata.get("is_sensitive", False)
            
            # Directory permissions drwxr-xr-x, file permissions -rw-r--r--
            if is_dir:
                perms = "drwxr-xr-x"
                size = "4096"
            elif is_sensitive:
                perms = "-rw-------"  # Sensitive files often have restricted permissions
                size = "2048"
            else:
                perms = "-rw-r--r--"
                size = "1024"
            
            # Format: perms links owner group size date time name
            lines.append(f"{perms}  2 root root {size:>8} Mar  4 10:30 {filename}")
        
        return "\n".join(lines)
    else:
        # Simple ls output - just filenames
        names = [f[0] for f in sorted(files)]
        return "  ".join(names)


def get_directory_tree(root_path: str = "/", max_depth: int = 2) -> str:
    """
    Generate a tree-style view of the filesystem.
    
    Useful for commands like 'tree' or 'find'.
    
    Args:
        root_path: Starting directory
        max_depth: Maximum depth to traverse
    
    Returns:
        Tree-style formatted string
    """
    def build_tree(path: str, depth: int, prefix: str = "") -> list[str]:
        if depth > max_depth:
            return []
        
        lines = []
        files = get_files_in_directory(path)
        
        for i, (filename, metadata) in enumerate(sorted(files)):
            is_last = i == len(files) - 1
            is_dir = metadata.get("is_directory", False)
            
            # Tree formatting characters
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "
            
            # Add directory indicator
            display_name = f"{filename}/" if is_dir else filename
            lines.append(f"{prefix}{connector}{display_name}")
            
            # Recurse into subdirectories
            if is_dir:
                subdir_path = f"{path}/{filename}".replace("//", "/")
                lines.extend(build_tree(subdir_path, depth + 1, prefix + extension))
        
        return lines
    
    tree_lines = [root_path]
    tree_lines.extend(build_tree(root_path, 0))
    return "\n".join(tree_lines)
