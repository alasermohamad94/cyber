# 🌐 Cyber Defense System - Web Dashboard

## 📋 Overview

A modern, professional web-based dashboard for the Cyber Defense System that provides real-time monitoring, threat management, and system control through an intuitive browser interface.

## 🚀 Quick Start

### **Method 1: Simple Launcher (Recommended)**
```bash
cd web_dashboard
python run_web_dashboard.py
```

### **Method 2: Manual Setup**
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### **Access the Dashboard**
- **Local**: http://localhost:8080
- **Network**: http://YOUR_IP:8080

## 🎯 Features

### **📊 Real-time Dashboard**
- **Live System Metrics**: CPU, Memory, Disk, Network monitoring
- **Interactive Charts**: Real-time performance graphs
- **Security Overview**: Entity trust scores and risk distribution
- **Recent Events**: Live security event feed
- **Quick Actions**: One-click security operations

### **🔍 Entity Analysis**
- **Advanced Analysis**: Comprehensive entity behavior analysis
- **Real-time Results**: Instant security decisions
- **Visual Feedback**: Clear risk indicators and recommendations
- **Historical Tracking**: Entity behavior over time

### **🛡️ Threat Management**
- **IP Blocking**: Instant IP address blocking
- **Security Reports**: Comprehensive security documentation
- **Alert System**: Real-time security notifications
- **Response Control**: Automated threat response

### **📈 Analytics**
- **Performance Trends**: Historical performance data
- **Security Analytics**: Threat patterns and trends
- **Resource Usage**: Detailed resource consumption
- **Custom Reports**: Exportable analytics data

## 🎨 Interface Features

### **Modern Design**
- **Responsive Layout**: Works on desktop, tablet, and mobile
- **Dark Theme**: Easy on the eyes for extended use
- **Real-time Updates**: Live data without page refresh
- **Interactive Elements**: Hover effects and smooth transitions

### **User Experience**
- **Intuitive Navigation**: Clear menu structure
- **Fast Loading**: Optimized for performance
- **Error Handling**: Graceful error messages
- **Accessibility**: WCAG compliant design

## 🔧 Technical Architecture

### **Backend Technologies**
- **Flask**: Lightweight web framework
- **Socket.IO**: Real-time bidirectional communication
- **psutil**: System monitoring library
- **Bootstrap**: Responsive UI framework

### **Frontend Technologies**
- **HTML5/CSS3**: Modern web standards
- **JavaScript ES6**: Modern JavaScript features
- **Chart.js**: Interactive data visualization
- **Bootstrap 5**: Professional UI components

### **Real-time Features**
- **WebSocket Connection**: Persistent client-server connection
- **Live Metrics**: Real-time system monitoring
- **Instant Alerts**: Immediate security notifications
- **Auto-refresh**: Automatic data updates

## 📱 Pages & Sections

### **1. Main Dashboard**
- System performance metrics
- Real-time charts
- Security overview
- Recent events
- Quick actions

### **2. Analytics Page**
- Historical performance data
- Security analytics
- Resource usage trends
- Custom date ranges

### **3. Threat Management**
- Entity analysis tools
- IP blocking interface
- Security event details
- Response management

### **4. Settings Page**
- System configuration
- Alert preferences
- User management
- Export options

## 🔐 Security Features

### **Authentication**
- **Session Management**: Secure user sessions
- **CSRF Protection**: Cross-site request forgery protection
- **Input Validation**: Comprehensive input sanitization
- **Rate Limiting**: Request rate limiting

### **Data Protection**
- **Secure Headers**: Security-focused HTTP headers
- **Data Encryption**: Sensitive data encryption
- **Access Control**: Role-based access control
- **Audit Logging**: Complete action audit trail

## 🚀 Deployment Options

### **Development**
```bash
# Local development
python run_web_dashboard.py
```

### **Production**
```bash
# Using Gunicorn (recommended)
pip install gunicorn eventlet
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:8080 app:app
```

### **Docker**
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8080

CMD ["python", "run_web_dashboard.py"]
```

### **Docker Compose**
```yaml
version: '3.8'
services:
  cyberdefense-web:
    build: .
    ports:
      - "8080:8080"
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
```

## 🔧 Configuration

### **Environment Variables**
```bash
# Server Configuration
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-secret-key

# Monitoring Settings
UPDATE_INTERVAL=2
MAX_DATA_POINTS=100
```

### **Custom Settings**
- **Refresh Rate**: Configure real-time update frequency
- **Data Retention**: Set historical data limits
- **Alert Thresholds**: Customize security alert levels
- **Export Formats**: Choose report export formats

## 📊 API Endpoints

### **System Metrics**
```
GET /api/system-metrics
Returns: Current system performance data
```

### **Security Overview**
```
GET /api/security-overview
Returns: Security statistics and recent events
```

### **Entity Analysis**
```
POST /api/analyze-entity
Body: {entity_id: string, entity_data: object}
Returns: Analysis results and security decisions
```

### **IP Blocking**
```
POST /api/block-ip
Body: {ip_address: string}
Returns: Block confirmation
```

### **Security Report**
```
GET /api/security-report
Returns: Comprehensive security report
```

## 🎯 Usage Examples

### **Analyzing an Entity**
1. Navigate to the dashboard
2. Click "Analyze Entity" button
3. Fill in entity details:
   - Entity ID: "server_01"
   - Type: "Server"
   - Connection Rate: 0.8
   - Failed Auth: 5
   - Total Auth: 20
4. Click "Analyze"
5. Review results and recommendations

### **Blocking an IP Address**
1. Click "Block IP" button
2. Enter IP address: "192.168.1.100"
3. Click "Block IP"
4. Confirm action
5. IP is now blocked and logged

### **Generating Security Report**
1. Click "Generate Report" button
2. Wait for report generation
3. Download report as text file
4. Review security posture and recommendations

## 🔍 Monitoring Capabilities

### **System Performance**
- **CPU Usage**: Real-time CPU monitoring
- **Memory Usage**: RAM utilization tracking
- **Disk Usage**: Storage capacity monitoring
- **Network I/O**: Data transfer monitoring
- **Active Connections**: Network connection tracking

### **Security Monitoring**
- **Entity Trust Scores**: Dynamic trust assessment
- **Risk Distribution**: Risk level categorization
- **Security Events**: Real-time event tracking
- **Threat Detection**: Automated threat identification
- **Response Actions**: Security response tracking

## 🚨 Alert System

### **Alert Types**
- **System Alerts**: Performance threshold breaches
- **Security Alerts**: Threat detection notifications
- **Connection Alerts**: Network status changes
- **Resource Alerts**: Resource exhaustion warnings

### **Notification Methods**
- **In-App Notifications**: Real-time browser notifications
- **Visual Indicators**: Color-coded alert system
- **Sound Alerts**: Optional audio notifications
- **Email Alerts**: Configurable email notifications

## 📈 Analytics & Reporting

### **Performance Analytics**
- **Historical Trends**: Long-term performance analysis
- **Resource Utilization**: Resource usage patterns
- **Bottleneck Identification**: Performance bottleneck detection
- **Capacity Planning**: Resource forecasting

### **Security Analytics**
- **Threat Patterns**: Attack pattern analysis
- **Risk Assessment**: Comprehensive risk evaluation
- **Compliance Reporting**: Regulatory compliance data
- **Incident Analysis**: Security incident breakdown

## 🛠️ Troubleshooting

### **Common Issues**

#### **Dashboard Not Loading**
```bash
# Check if port is available
netstat -an | grep 8080

# Check dependencies
pip list | grep -E "(Flask|psutil|SocketIO)"
```

#### **Real-time Updates Not Working**
```bash
# Check WebSocket connection
# Open browser developer tools
# Check Console for errors
# Verify Socket.IO connection
```

#### **High Memory Usage**
```bash
# Reduce data retention
# Set MAX_DATA_POINTS environment variable
# Monitor memory usage
```

### **Performance Optimization**
- **Data Limits**: Configure appropriate data retention limits
- **Update Frequency**: Adjust real-time update intervals
- **Browser Caching**: Enable browser caching
- **Compression**: Enable gzip compression

## 🔒 Security Best Practices

### **Production Deployment**
- **HTTPS**: Use SSL/TLS encryption
- **Firewall**: Configure proper firewall rules
- **Authentication**: Implement user authentication
- **Access Control**: Restrict admin access
- **Regular Updates**: Keep dependencies updated

### **Network Security**
- **VPN Access**: Use VPN for remote access
- **IP Whitelisting**: Restrict access by IP
- **Rate Limiting**: Implement request rate limits
- **Monitoring**: Monitor access logs
- **Backup**: Regular data backups

## 📞 Support

### **Documentation**
- **User Guide**: Complete usage instructions
- **API Documentation**: Detailed API reference
- **Deployment Guide**: Production deployment instructions
- **Troubleshooting**: Common issues and solutions

### **Getting Help**
- **GitHub Issues**: Report bugs and request features
- **Community Forum**: User discussions and support
- **Documentation**: Comprehensive online documentation
- **Email Support**: Direct technical support

---

## 🎉 **Ready to Launch!**

Your Cyber Defense System Web Dashboard is now ready for deployment!

### **Quick Start:**
```bash
cd web_dashboard
python run_web_dashboard.py
```

### **Access:**
- **Local**: http://localhost:8080
- **Network**: http://YOUR_IP:8080

### **Features Available:**
- ✅ Real-time system monitoring
- ✅ Interactive security management
- ✅ Advanced entity analysis
- ✅ Professional web interface
- ✅ Mobile-responsive design
- ✅ Real-time notifications
- ✅ Comprehensive reporting

**🚀 Your professional web dashboard is ready!**
