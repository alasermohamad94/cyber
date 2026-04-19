# 🚀 Cyber Defense System - Deployment Guide

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Steps](#installation-steps)
3. [Configuration](#configuration)
4. [Deployment Options](#deployment-options)
5. [Production Deployment](#production-deployment)
6. [Security Considerations](#security-considerations)
7. [Monitoring & Maintenance](#monitoring--maintenance)
8. [Troubleshooting](#troubleshooting)

---

## 🔧 System Requirements

### **Minimum Requirements**
- **OS**: Linux (Ubuntu 20.04+, CentOS 7+, RHEL 7+) or Windows Server 2016+
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 20 GB free space
- **Network**: Stable internet connection
- **Python**: 3.8 or higher

### **Recommended Requirements**
- **OS**: Linux (Ubuntu 22.04 LTS, CentOS 8+, RHEL 8+)
- **CPU**: 4 cores, 2.5 GHz or higher
- **RAM**: 16 GB or higher
- **Storage**: 100 GB SSD storage
- **Network**: Gigabit connection
- **Python**: 3.10 or higher

### **Software Dependencies**
```bash
# Required Python packages
psutil>=5.9.0
pytest>=7.0.0
dataclasses (built-in for Python 3.7+)
threading (built-in)
socket (built-in)
datetime (built-in)
collections (built-in)
```

---

## 📦 Installation Steps

### **Step 1: System Preparation**

#### **For Linux/Ubuntu:**
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and development tools
sudo apt install python3 python3-pip python3-venv git -y

# Install system monitoring tools
sudo apt install htop iotop nethogs -y
```

#### **For Windows Server:**
```powershell
# Install Python from python.org or Microsoft Store
# Install Git for Windows
# Ensure Python is in PATH
```

### **Step 2: Create Project Directory**
```bash
# Create dedicated user for security (Linux)
sudo useradd -m -s /bin/bash cyberdefense
sudo usermod -aG sudo cyberdefense

# Switch to cyberdefense user
sudo su - cyberdefense

# Create project directory
mkdir -p /opt/cyber-defense-system
cd /opt/cyber-defense-system
```

### **Step 3: Clone or Copy Project**
```bash
# Option 1: If using Git
git clone <repository-url> /opt/cyber-defense-system

# Option 2: Copy project files
# Copy all project files to /opt/cyber-defense-system/
```

### **Step 4: Create Virtual Environment**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# For Windows (Command Prompt)
# venv\Scripts\activate.bat

# For Windows (PowerShell)
# venv\Scripts\Activate.ps1
```

### **Step 5: Install Dependencies**
```bash
# Install required packages
pip install psutil pytest

# Verify installation
python -c "import psutil; print('psutil version:', psutil.__version__)"
```

### **Step 6: Set Permissions**
```bash
# Make scripts executable (Linux)
chmod +x *.py
chmod +x dashboard/*.py

# Set proper ownership
sudo chown -R cyberdefense:cyberdefense /opt/cyber-defense-system
```

---

## ⚙️ Configuration

### **Environment Configuration**
Create configuration file:
```bash
# Create config directory
mkdir -p config

# Create environment file
cat > config/.env << EOF
# Cyber Defense System Configuration
SYSTEM_NAME=production-server
SECURITY_LEVEL=high
LOG_LEVEL=INFO
DATA_RETENTION_DAYS=30
ALERT_EMAIL=admin@yourdomain.com
BACKUP_SCHEDULE=0 2 * * *
EOF
```

### **System Service Configuration**

#### **Linux Systemd Service:**
```bash
# Create systemd service file
sudo cat > /etc/systemd/system/cyberdefense.service << EOF
[Unit]
Description=Cyber Defense System
After=network.target

[Service]
Type=simple
User=cyberdefense
Group=cyberdefense
WorkingDirectory=/opt/cyber-defense-system
Environment=PATH=/opt/cyber-defense-system/venv/bin
ExecStart=/opt/cyber-defense-system/venv/bin/python dashboard/server_control_center_ascii.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable cyberdefense
sudo systemctl start cyberdefense
```

#### **Windows Service:**
```powershell
# Create Windows service using NSSM (Non-Sucking Service Manager)
# Download NSSM from https://nssm.cc/download

# Install service
nssm install CyberDefense "C:\opt\cyber-defense-system\venv\Scripts\python.exe"
nssm set CyberDefense Arguments "dashboard\server_control_center_ascii.py"
nssm set CyberDefense DisplayName "Cyber Defense System"
nssm set CyberDefense Description "Advanced server monitoring and security management system"
nssm set CyberDefense Start SERVICE_AUTO_START

# Start service
nssm start CyberDefense
```

---

## 🌐 Deployment Options

### **Option 1: Standalone Server**
**Best for:** Small to medium organizations, single server monitoring

**Pros:**
- Simple setup
- Low cost
- Full control
- Easy maintenance

**Cons:**
- Single point of failure
- Limited scalability
- Manual backup required

### **Option 2: Docker Container**
**Best for:** Development, testing, and consistent deployments

**Create Dockerfile:**
```dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Install Python dependencies
RUN pip install --no-cache-dir psutil pytest

# Create non-root user
RUN useradd -m -u 1000 cyberdefense && chown -R cyberdefense:cyberdefense /app
USER cyberdefense

# Expose port (if web interface added)
EXPOSE 8080

# Run the application
CMD ["python", "dashboard/server_control_center_ascii.py"]
```

**Build and Run:**
```bash
# Build image
docker build -t cyber-defense-system .

# Run container
docker run -d \
  --name cyberdefense \
  --restart unless-stopped \
  -v /opt/cyber-defense-system/data:/app/data \
  cyber-defense-system
```

### **Option 3: Cloud Deployment**
**Best for:** Large organizations, multi-server environments

#### **AWS Deployment:**
```bash
# Launch EC2 instance (t3.medium or larger)
# Install Docker
# Deploy using Docker Compose

# docker-compose.yml
version: '3.8'
services:
  cyberdefense:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - SYSTEM_NAME=aws-production
      - SECURITY_LEVEL=high
    restart: unless-stopped
```

#### **Azure Deployment:**
```bash
# Create Azure Container Instance
# Use Azure CLI or Azure Portal
# Deploy Docker container
```

---

## 🏭 Production Deployment

### **Pre-Deployment Checklist**

#### **Security Hardening:**
```bash
# Update all packages
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 8080/tcp  # If web interface
sudo ufw deny 23  # Block telnet
sudo ufw deny 21  # Block FTP

# Disable unnecessary services
sudo systemctl disable apache2
sudo systemctl disable mysql
sudo systemctl disable postfix

# Configure fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```

#### **Performance Optimization:**
```bash
# Optimize system limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Configure sysctl
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### **Database Setup (Optional)**
For persistent storage of security events:
```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE cyberdefense;
CREATE USER cyberdefense_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE cyberdefense TO cyberdefense_user;
\q
EOF
```

### **Backup Configuration**
```bash
# Create backup script
cat > /opt/cyber-defense-system/scripts/backup.sh << EOF
#!/bin/bash
BACKUP_DIR="/opt/backups/cyberdefense"
DATE=\$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p \$BACKUP_DIR

# Backup configuration and data
tar -czf \$BACKUP_DIR/cyberdefense_\$DATE.tar.gz \
    /opt/cyber-defense-system/config \
    /opt/cyber-defense-system/data \
    /opt/cyber-defense-system/logs

# Keep only last 7 days of backups
find \$BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: cyberdefense_\$DATE.tar.gz"
EOF

chmod +x /opt/cyber-defense-system/scripts/backup.sh

# Add to crontab for daily backups
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/cyber-defense-system/scripts/backup.sh") | crontab -
```

### **Monitoring Setup**
```bash
# Install monitoring tools
sudo apt install prometheus grafana -y

# Configure Prometheus to monitor the system
cat > /etc/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cyberdefense'
    static_configs:
      - targets: ['localhost:8080']
EOF

sudo systemctl restart prometheus
sudo systemctl enable prometheus
```

---

## 🔒 Security Considerations

### **Access Control**
```bash
# Create user groups
sudo groupadd cyberdefense-admins
sudo groupadd cyberdefense-operators

# Add users to appropriate groups
sudo usermod -aG cyberdefense-admins admin_user
sudo usermod -aG cyberdefense-operators operator_user

# Set file permissions
sudo chown -R root:cyberdefense-admins /opt/cyber-defense-system
sudo chmod -R 770 /opt/cyber-defense-system
```

### **Network Security**
```bash
# Configure iptables rules
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### **SSL/TLS Configuration** (if web interface added)
```bash
# Install Let's Encrypt
sudo apt install certbot python3-certbot-nginx -y

# Generate SSL certificate
sudo certbot --nginx -d yourdomain.com
```

### **Audit Logging**
```bash
# Configure auditd
sudo apt install auditd -y

# Add audit rules
sudo auditctl -w /opt/cyber-defense-system -p rwxa -k cyberdefense
sudo auditctl -w /etc/systemd/system/cyberdefense.service -p rwxa -k cyberdefense
```

---

## 📊 Monitoring & Maintenance

### **Health Check Script**
```bash
cat > /opt/cyber-defense-system/scripts/health_check.sh << EOF
#!/bin/bash

# Check if service is running
if ! systemctl is-active --quiet cyberdefense; then
    echo "CRITICAL: Cyber Defense service is not running"
    systemctl restart cyberdefense
fi

# Check disk space
DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ \$DISK_USAGE -gt 80 ]; then
    echo "WARNING: Disk usage is \${DISK_USAGE}%"
fi

# Check memory usage
MEM_USAGE=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
if [ \$MEM_USAGE -gt 80 ]; then
    echo "WARNING: Memory usage is \${MEM_USAGE}%"
fi

# Check log file sizes
LOG_SIZE=\$(du -sh /opt/cyber-defense-system/logs | awk '{print \$1}' | sed 's/[^0-9]//g')
if [ \$LOG_SIZE -gt 1000 ]; then  # 1GB
    echo "WARNING: Log files are large (\$LOG_SIZE MB)"
fi

echo "Health check completed at \$(date)"
EOF

chmod +x /opt/cyber-defense-system/scripts/health_check.sh

# Add to crontab for every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/cyber-defense-system/scripts/health_check.sh >> /var/log/cyberdefense-health.log 2>&1") | crontab -
```

### **Log Rotation**
```bash
# Create logrotate configuration
sudo cat > /etc/logrotate.d/cyberdefense << EOF
/opt/cyber-defense-system/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 cyberdefense cyberdefense
    postrotate
        systemctl reload cyberdefense
    endscript
}
EOF
```

### **Performance Monitoring**
```bash
# Create performance monitoring script
cat > /opt/cyber-defense-system/scripts/performance_monitor.sh << EOF
#!/bin/bash

# Record system metrics
DATE=\$(date +%Y-%m-%d_%H:%M:%S)
CPU=\$(top -bn1 | grep "Cpu(s)" | awk '{print \$2}' | sed 's/%us,//')
MEM=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
DISK=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')

# Log to file
echo "\$DATE,CPU:\$CPU,MEM:\$MEM,DISK:\$DISK" >> /opt/cyber-defense-system/data/performance.log

# Alert if thresholds exceeded
if [ \${CPU%.*} -gt 80 ] || [ \$MEM -gt 80 ] || [ \${DISK%.*} -gt 80 ]; then
    echo "PERFORMANCE ALERT: CPU=\$CPU%, MEM=\$MEM%, DISK=\$DISK%" | mail -s "Cyber Defense Performance Alert" admin@yourdomain.com
fi
EOF

chmod +x /opt/cyber-defense-system/scripts/performance_monitor.sh
```

---

## 🔧 Troubleshooting

### **Common Issues & Solutions**

#### **1. Service Won't Start**
```bash
# Check service status
sudo systemctl status cyberdefense

# Check logs
sudo journalctl -u cyberdefense -f

# Common fixes:
# - Check file permissions
# - Verify Python path
# - Check virtual environment
# - Verify configuration files
```

#### **2. High Memory Usage**
```bash
# Check memory usage
ps aux | grep python

# Restart service
sudo systemctl restart cyberdefense

# Optimize configuration
# Reduce monitoring frequency
# Limit history retention
```

#### **3. Network Connection Issues**
```bash
# Check firewall rules
sudo ufw status verbose

# Check port availability
netstat -tlnp | grep :8080

# Test connectivity
telnet localhost 8080
```

#### **4. Permission Errors**
```bash
# Check file ownership
ls -la /opt/cyber-defense-system/

# Fix permissions
sudo chown -R cyberdefense:cyberdefense /opt/cyber-defense-system
sudo chmod -R 755 /opt/cyber-defense-system
```

#### **5. Performance Issues**
```bash
# Check system resources
htop
iotop
nethogs

# Optimize system
sudo sysctl -w vm.swappiness=10
sudo sysctl -w net.core.somaxconn=1024
```

### **Emergency Procedures**

#### **Service Recovery:**
```bash
# Emergency restart
sudo systemctl restart cyberdefense

# Full system restart
sudo systemctl restart cyberdefense
sudo systemctl daemon-reload
sudo systemctl start cyberdefense

# Check logs after restart
sudo journalctl -u cyberdefense --since "5 minutes ago"
```

#### **Data Recovery:**
```bash
# Restore from backup
sudo tar -xzf /opt/backups/cyberdefense/cyberdefense_YYYYMMDD_HHMMSS.tar.gz -C /

# Restart service after restore
sudo systemctl restart cyberdefense
```

---

## 📞 Support & Maintenance

### **Regular Maintenance Tasks**
- **Daily**: Check service status, review logs
- **Weekly**: Review performance metrics, update system
- **Monthly**: Security updates, backup verification
- **Quarterly**: Performance tuning, security audit

### **Contact Information**
- **System Administrator**: admin@yourdomain.com
- **Security Team**: security@yourdomain.com
- **Emergency Contact**: +1-555-0123

### **Documentation**
- User Guide: `SERVER_CONTROL_GUIDE.md`
- API Documentation: `API_DOCS.md`
- Architecture: `ARCHITECTURE.md`

---

## 🎯 Quick Start Summary

### **For Immediate Deployment:**
```bash
# 1. Clone/copy project to /opt/cyber-defense-system
# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install psutil pytest

# 4. Run system
python dashboard/server_control_center_ascii.py

# 5. For production, create systemd service
sudo systemctl enable cyberdefense
sudo systemctl start cyberdefense
```

### **Verification:**
```bash
# Check service status
sudo systemctl status cyberdefense

# Test functionality
python -c "from main import CyberDefenseSystem; print('System OK')"

# Monitor logs
sudo journalctl -u cyberdefense -f
```

---

**🎉 Your Cyber Defense System is now ready for production deployment!**

For additional support or questions, refer to the documentation or contact the system administrator.
