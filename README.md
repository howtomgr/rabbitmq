# RabbitMQ Installation Guide

RabbitMQ is a free and open-source message-queueing software and broker written in Erlang. Originally developed by Rabbit Technologies and now owned by VMware, RabbitMQ implements the Advanced Message Queuing Protocol (AMQP) and provides message routing, queuing, and delivery guarantees. It serves as a FOSS alternative to commercial message brokers like IBM MQ, Oracle WebLogic Server, or Microsoft Azure Service Bus, offering enterprise-grade reliability, clustering, and high availability without licensing costs, with features like message persistence, flexible routing, and cross-language support.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended for production)
  - RAM: 1GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum (SSD recommended for message persistence)
  - Network: Stable connectivity for clustering setups
- **Operating System**: 
  - Linux: Any modern distribution with kernel 3.2+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 5672 (AMQP 0-9-1 and 1.0)
  - Port 15672 (HTTP Management API)
  - Port 25672 (Erlang distribution for clustering)
  - Port 4369 (EPMD - Erlang Port Mapper Daemon)
  - Port 35672-35682 (CLI tools)
- **Dependencies**:
  - Erlang/OTP (version 23.2+ for RabbitMQ 3.9+)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Add RabbitMQ repository
curl -s https://packagecloud.io/install/repositories/rabbitmq/rabbitmq-server/script.rpm.sh | sudo bash

# Add Erlang repository
curl -s https://packagecloud.io/install/repositories/rabbitmq/erlang/script.rpm.sh | sudo bash

# Install Erlang
sudo yum install -y erlang

# Install RabbitMQ server
sudo yum install -y rabbitmq-server

# Enable and start service
sudo systemctl enable --now rabbitmq-server

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Configure firewall
sudo firewall-cmd --permanent --add-port=5672/tcp
sudo firewall-cmd --permanent --add-port=15672/tcp
sudo firewall-cmd --permanent --add-port=25672/tcp
sudo firewall-cmd --reload

# Create admin user
sudo rabbitmqctl add_user admin SecureAdminPassword123!
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
sudo rabbitmqctl delete_user guest
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install prerequisite packages
sudo apt install -y curl gnupg apt-transport-https

# Add RabbitMQ signing key
curl -fsSL https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA | sudo gpg --dearmor -o /usr/share/keyrings/com.rabbitmq.team.gpg

# Add RabbitMQ repository
echo "deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://ppa1.novemberain.com/rabbitmq/rabbitmq-server/deb/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/rabbitmq.list

# Add Erlang repository
echo "deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://ppa1.novemberain.com/rabbitmq/rabbitmq-erlang/deb/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/rabbitmq-erlang.list

# Update package index
sudo apt update

# Install Erlang and RabbitMQ
sudo apt install -y erlang-base erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets erlang-mnesia erlang-os-mon erlang-parsetools erlang-public-key erlang-runtime-tools erlang-snmp erlang-ssl erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl
sudo apt install -y rabbitmq-server

# Enable and start service
sudo systemctl enable --now rabbitmq-server

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Configure firewall
sudo ufw allow 5672
sudo ufw allow 15672

# Create admin user
sudo rabbitmqctl add_user admin SecureAdminPassword123!
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
sudo rabbitmqctl delete_user guest
```

### Arch Linux

```bash
# Install RabbitMQ from official repositories
sudo pacman -S rabbitmq

# Install Erlang (dependency)
sudo pacman -S erlang-nox

# Create rabbitmq user if not exists
sudo useradd -r -s /sbin/nologin -d /var/lib/rabbitmq -c "RabbitMQ messaging server" rabbitmq

# Enable and start service
sudo systemctl enable --now rabbitmq

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Create admin user
sudo rabbitmqctl add_user admin SecureAdminPassword123!
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
sudo rabbitmqctl delete_user guest

# Configuration location: /etc/rabbitmq/
```

### Alpine Linux

```bash
# Install RabbitMQ
apk add --no-cache rabbitmq-server rabbitmq-server-management

# Install Erlang
apk add --no-cache erlang

# Create rabbitmq user if not exists
adduser -D -H -s /sbin/nologin -G rabbitmq rabbitmq

# Set permissions
chown -R rabbitmq:rabbitmq /var/lib/rabbitmq /var/log/rabbitmq

# Enable and start service
rc-update add rabbitmq default
rc-service rabbitmq start

# Enable management plugin
rabbitmq-plugins enable rabbitmq_management

# Create admin user
rabbitmqctl add_user admin SecureAdminPassword123!
rabbitmqctl set_user_tags admin administrator
rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
rabbitmqctl delete_user guest
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y rabbitmq-server erlang

# SLES 15
sudo SUSEConnect -p sle-module-server-applications/15.5/x86_64
sudo zypper install -y rabbitmq-server erlang

# Enable and start service
sudo systemctl enable --now rabbitmq-server

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Configure firewall
sudo firewall-cmd --permanent --add-port=5672/tcp
sudo firewall-cmd --permanent --add-port=15672/tcp
sudo firewall-cmd --reload

# Create admin user
sudo rabbitmqctl add_user admin SecureAdminPassword123!
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
sudo rabbitmqctl delete_user guest
```

### macOS

```bash
# Using Homebrew
brew install rabbitmq

# Start RabbitMQ service
brew services start rabbitmq

# Or run manually
sudo rabbitmq-server

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Create admin user
sudo rabbitmqctl add_user admin SecureAdminPassword123!
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
sudo rabbitmqctl delete_user guest

# Configuration location: /usr/local/etc/rabbitmq/
# Alternative: /opt/homebrew/etc/rabbitmq/ (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install rabbitmq erlang

# Using ports
cd /usr/ports/net/rabbitmq
make install clean

# Enable RabbitMQ
echo 'rabbitmq_enable="YES"' >> /etc/rc.conf

# Start service
service rabbitmq start

# Enable management plugin
rabbitmq-plugins enable rabbitmq_management

# Create admin user
rabbitmqctl add_user admin SecureAdminPassword123!
rabbitmqctl set_user_tags admin administrator
rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
rabbitmqctl delete_user guest

# Configuration location: /usr/local/etc/rabbitmq/
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install rabbitmq

# Method 2: Using Scoop
scoop install rabbitmq

# Method 3: Manual installation
# Download from https://www.rabbitmq.com/download.html
# Install Erlang first, then RabbitMQ

# Install as Windows service (automatic with installer)
# The service is named "RabbitMQ"

# Enable management plugin
rabbitmq-plugins.bat enable rabbitmq_management

# Create admin user
rabbitmqctl.bat add_user admin SecureAdminPassword123!
rabbitmqctl.bat set_user_tags admin administrator
rabbitmqctl.bat set_permissions -p / admin ".*" ".*" ".*"

# Remove guest user (security)
rabbitmqctl.bat delete_user guest

# Configuration location: %APPDATA%\RabbitMQ\
```

## Initial Configuration

### First-Run Setup

1. **Create rabbitmq user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/rabbitmq -s /sbin/nologin -c "RabbitMQ messaging server" rabbitmq
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/rabbitmq/rabbitmq.conf`
- Debian/Ubuntu: `/etc/rabbitmq/rabbitmq.conf`
- Arch Linux: `/etc/rabbitmq/rabbitmq.conf`
- Alpine Linux: `/etc/rabbitmq/rabbitmq.conf`
- openSUSE/SLES: `/etc/rabbitmq/rabbitmq.conf`
- macOS: `/usr/local/etc/rabbitmq/rabbitmq.conf`
- FreeBSD: `/usr/local/etc/rabbitmq/rabbitmq.conf`
- Windows: `%APPDATA%\RabbitMQ\rabbitmq.conf`

3. **Essential settings to change**:

```ini
# /etc/rabbitmq/rabbitmq.conf
# Network and clustering
listeners.tcp.default = 5672
management.tcp.port = 15672

# Security
loopback_users.guest = false
default_user = admin
default_pass = SecureAdminPassword123!

# Logging
log.file.level = info
log.file = /var/log/rabbitmq/rabbitmq.log
log.file.rotation.size = 10485760

# Memory and disk limits
vm_memory_high_watermark.relative = 0.6
disk_free_limit.absolute = 1GB

# Message TTL and limits
default_user_tags.administrator = true
heartbeat = 60

# Clustering (if multiple nodes)
cluster_formation.peer_discovery_backend = rabbit_peer_discovery_classic_config
cluster_formation.classic_config.nodes.1 = rabbit@node1
cluster_formation.classic_config.nodes.2 = rabbit@node2
```

### Testing Initial Setup

```bash
# Check if RabbitMQ is running
sudo systemctl status rabbitmq-server

# Test connection
rabbitmqctl status

# Check cluster status
rabbitmqctl cluster_status

# List users
rabbitmqctl list_users

# List virtual hosts
rabbitmqctl list_vhosts

# Test management interface
curl -u admin:SecureAdminPassword123! http://localhost:15672/api/overview

# Test AMQP connection
rabbitmqctl eval 'rabbit_networking:tcp_listener_started(5672).'
```

**WARNING:** Remove or disable the default guest user and enable proper authentication!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable RabbitMQ to start on boot
sudo systemctl enable rabbitmq-server

# Start RabbitMQ
sudo systemctl start rabbitmq-server

# Stop RabbitMQ
sudo systemctl stop rabbitmq-server

# Restart RabbitMQ
sudo systemctl restart rabbitmq-server

# Reload configuration (graceful)
sudo rabbitmqctl eval 'application:stop(rabbitmq_management_agent), application:start(rabbitmq_management_agent).'

# Check status
sudo systemctl status rabbitmq-server

# View logs
sudo journalctl -u rabbitmq-server -f
```

### OpenRC (Alpine Linux)

```bash
# Enable RabbitMQ to start on boot
rc-update add rabbitmq default

# Start RabbitMQ
rc-service rabbitmq start

# Stop RabbitMQ
rc-service rabbitmq stop

# Restart RabbitMQ
rc-service rabbitmq restart

# Check status
rc-service rabbitmq status

# View logs
tail -f /var/log/rabbitmq/rabbit@$(hostname).log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'rabbitmq_enable="YES"' >> /etc/rc.conf

# Start RabbitMQ
service rabbitmq start

# Stop RabbitMQ
service rabbitmq stop

# Restart RabbitMQ
service rabbitmq restart

# Check status
service rabbitmq status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start rabbitmq
brew services stop rabbitmq
brew services restart rabbitmq

# Check status
brew services list | grep rabbitmq

# Manual control
sudo rabbitmq-server -detached
sudo rabbitmqctl shutdown
```

### Windows Service Manager

```powershell
# Start RabbitMQ service
net start RabbitMQ

# Stop RabbitMQ service
net stop RabbitMQ

# Using PowerShell
Start-Service RabbitMQ
Stop-Service RabbitMQ
Restart-Service RabbitMQ

# Check status
Get-Service RabbitMQ

# View logs
Get-EventLog -LogName Application -Source RabbitMQ
```

## Advanced Configuration

### High Availability Configuration

```ini
# Cluster configuration
cluster_formation.peer_discovery_backend = rabbit_peer_discovery_classic_config
cluster_formation.classic_config.nodes.1 = rabbit@rabbitmq-1
cluster_formation.classic_config.nodes.2 = rabbit@rabbitmq-2
cluster_formation.classic_config.nodes.3 = rabbit@rabbitmq-3

# Enable quorum queues by default
default_queue_type = quorum

# HA policy for classic queues
queue_master_locator = min-masters
```

### Advanced Security Settings

```ini
# SSL/TLS configuration
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/ssl/ca_certificate.pem
ssl_options.certfile = /etc/rabbitmq/ssl/server_certificate.pem
ssl_options.keyfile = /etc/rabbitmq/ssl/server_key.pem
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = true

# Management over HTTPS
management.ssl.port = 15671
management.ssl.cacertfile = /etc/rabbitmq/ssl/ca_certificate.pem
management.ssl.certfile = /etc/rabbitmq/ssl/server_certificate.pem
management.ssl.keyfile = /etc/rabbitmq/ssl/server_key.pem

# Authentication backends
auth_backends.1 = rabbit_auth_backend_ldap
auth_backends.2 = rabbit_auth_backend_internal

# LDAP configuration
auth_ldap.servers.1 = ldap.example.com
auth_ldap.user_dn_pattern = cn=${username},ou=users,dc=example,dc=com
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/rabbitmq
upstream rabbitmq_management {
    server 127.0.0.1:15672 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:15673 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 80;
    server_name rabbitmq.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name rabbitmq.example.com;

    ssl_certificate /etc/letsencrypt/live/rabbitmq.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rabbitmq.example.com/privkey.pem;

    location / {
        proxy_pass http://rabbitmq_management;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for management UI
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend rabbitmq_management_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/rabbitmq.pem
    redirect scheme https if !{ ssl_fc }
    default_backend rabbitmq_management_servers

backend rabbitmq_management_servers
    mode http
    balance roundrobin
    option httpchk GET /api/aliveness-test/%2F
    server rabbitmq1 127.0.0.1:15672 check
    server rabbitmq2 127.0.0.1:15673 check backup

frontend rabbitmq_amqp_frontend
    bind *:5672
    mode tcp
    default_backend rabbitmq_amqp_servers

backend rabbitmq_amqp_servers
    mode tcp
    balance roundrobin
    server rabbitmq1 127.0.0.1:5672 check
    server rabbitmq2 127.0.0.1:5673 check backup
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate SSL certificates for RabbitMQ
sudo mkdir -p /etc/rabbitmq/ssl

# Create CA certificate
sudo openssl genrsa -out /etc/rabbitmq/ssl/ca_key.pem 4096
sudo openssl req -new -x509 -days 3650 -key /etc/rabbitmq/ssl/ca_key.pem -out /etc/rabbitmq/ssl/ca_certificate.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=RabbitMQ-CA"

# Create server certificate
sudo openssl genrsa -out /etc/rabbitmq/ssl/server_key.pem 4096
sudo openssl req -new -key /etc/rabbitmq/ssl/server_key.pem -out /etc/rabbitmq/ssl/server_certificate_request.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=rabbitmq.example.com"
sudo openssl x509 -req -in /etc/rabbitmq/ssl/server_certificate_request.pem -CA /etc/rabbitmq/ssl/ca_certificate.pem -CAkey /etc/rabbitmq/ssl/ca_key.pem -CAcreateserial -out /etc/rabbitmq/ssl/server_certificate.pem -days 365

# Create client certificate
sudo openssl genrsa -out /etc/rabbitmq/ssl/client_key.pem 4096
sudo openssl req -new -key /etc/rabbitmq/ssl/client_key.pem -out /etc/rabbitmq/ssl/client_certificate_request.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=rabbitmq-client"
sudo openssl x509 -req -in /etc/rabbitmq/ssl/client_certificate_request.pem -CA /etc/rabbitmq/ssl/ca_certificate.pem -CAkey /etc/rabbitmq/ssl/ca_key.pem -CAcreateserial -out /etc/rabbitmq/ssl/client_certificate.pem -days 365

# Set permissions
sudo chown -R rabbitmq:rabbitmq /etc/rabbitmq/ssl
sudo chmod 600 /etc/rabbitmq/ssl/*_key.pem
sudo chmod 644 /etc/rabbitmq/ssl/*_certificate.pem /etc/rabbitmq/ssl/ca_certificate.pem
```

### User Management and Access Control

```bash
# Create application user
sudo rabbitmqctl add_user myapp SecureAppPassword123!
sudo rabbitmqctl set_permissions -p / myapp "myapp\..*" "myapp\..*" "myapp\..*"

# Create monitoring user
sudo rabbitmqctl add_user monitoring MonitorPassword123!
sudo rabbitmqctl set_user_tags monitoring monitoring
sudo rabbitmqctl set_permissions -p / monitoring "" "" ".*"

# Create backup user
sudo rabbitmqctl add_user backup BackupPassword123!
sudo rabbitmqctl set_user_tags backup management
sudo rabbitmqctl set_permissions -p / backup "" "" ".*"

# Create virtual hosts
sudo rabbitmqctl add_vhost production
sudo rabbitmqctl add_vhost staging

# Set permissions for virtual hosts
sudo rabbitmqctl set_permissions -p production myapp ".*" ".*" ".*"
sudo rabbitmqctl set_permissions -p staging myapp ".*" ".*" ".*"

# Set resource limits
sudo rabbitmqctl set_user_limits myapp '{"max-connections": 100, "max-channels": 1000}'
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 5672
sudo ufw allow from 192.168.1.0/24 to any port 15672
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=rabbitmq
sudo firewall-cmd --permanent --zone=rabbitmq --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=rabbitmq --add-port=5672/tcp
sudo firewall-cmd --permanent --zone=rabbitmq --add-port=15672/tcp
sudo firewall-cmd --permanent --zone=rabbitmq --add-port=25672/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 5672 -j ACCEPT
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 15672 -j ACCEPT
sudo iptables -save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port {5672, 15672, 25672}

# Windows Firewall
New-NetFirewallRule -DisplayName "RabbitMQ AMQP" -Direction Inbound -Protocol TCP -LocalPort 5672 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "RabbitMQ Management" -Direction Inbound -Protocol TCP -LocalPort 15672 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### Queue and Exchange Configuration

```bash
# Create exchanges
rabbitmqctl eval 'rabbit_exchange:declare({resource, <<"/">>, exchange, <<"logs">>}, topic, true, false, false, []).'
rabbitmqctl eval 'rabbit_exchange:declare({resource, <<"/">>, exchange, <<"tasks">>}, direct, true, false, false, []).'

# Create queues
rabbitmqctl eval 'rabbit_amqqueue:declare({resource, <<"/">>, queue, <<"error_logs">>}, true, false, [], none, <<"/">>).'
rabbitmqctl eval 'rabbit_amqqueue:declare({resource, <<"/">>, queue, <<"task_queue">>}, true, false, [], none, <<"/">>).'

# Create bindings
rabbitmqctl eval 'rabbit_binding:add({binding, {resource, <<"/">>, exchange, <<"logs">>}, <<"error">>, {resource, <<"/">>, queue, <<"error_logs">>}, []}).'

# Set queue policies for HA
sudo rabbitmqctl set_policy ha-all ".*" '{"ha-mode":"all","ha-sync-mode":"automatic"}'

# Set TTL policy
sudo rabbitmqctl set_policy TTL ".*" '{"message-ttl":3600000}' --apply-to queues

# Set queue length limit
sudo rabbitmqctl set_policy max-length ".*" '{"max-length":10000}' --apply-to queues
```

### Shovel Configuration (Message Transfer)

```bash
# Install shovel plugin
sudo rabbitmq-plugins enable rabbitmq_shovel
sudo rabbitmq-plugins enable rabbitmq_shovel_management

# Create shovel (via management API)
curl -u admin:SecureAdminPassword123! -X PUT \
  http://localhost:15672/api/parameters/shovel/%2F/my-shovel \
  -H "Content-Type: application/json" \
  -d '{
    "value": {
      "src-protocol": "amqp091",
      "src-uri": "amqp://guest:guest@source-server:5672/%2F",
      "src-queue": "source-queue",
      "dest-protocol": "amqp091",
      "dest-uri": "amqp://guest:guest@dest-server:5672/%2F",
      "dest-queue": "dest-queue"
    }
  }'
```

## Performance Optimization

### System Tuning

```bash
# RabbitMQ-specific system optimizations
sudo tee -a /etc/sysctl.conf <<EOF
# RabbitMQ optimizations
vm.swappiness = 1
net.core.somaxconn = 4096
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 100000
EOF

sudo sysctl -p

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
rabbitmq soft nofile 65536
rabbitmq hard nofile 65536
EOF

# Set Erlang VM parameters
sudo tee /etc/rabbitmq/rabbitmq-env.conf <<EOF
RABBITMQ_SERVER_ERL_ARGS="+K true +A 128 +P 1048576"
RABBITMQ_CTL_ERL_ARGS="+K true"
EOF
```

### RabbitMQ Performance Configuration

```ini
# High-performance RabbitMQ configuration
# /etc/rabbitmq/rabbitmq.conf

# Memory and disk
vm_memory_high_watermark.relative = 0.4
vm_memory_high_watermark_paging_ratio = 0.3
disk_free_limit.absolute = 2GB

# Clustering and replication
cluster_partition_handling = pause_minority
cluster_keepalive_interval = 10000

# Connection and channel limits
connection_max = 65536
channel_max = 2047

# Message store
msg_store_file_size_limit = 16777216
queue_index_embed_msgs_below = 4096

# Lazy queues (for large queues)
lazy_queue_explicit_gc_run_operation_threshold = 1000

# Mnesia table loading
mnesia_table_loading_retry_timeout = 30000
mnesia_table_loading_retry_limit = 10
```

### Queue Optimization

```bash
# Enable lazy queues for large message backlogs
rabbitmqctl set_policy lazy-queue ".*" '{"queue-mode":"lazy"}' --apply-to queues

# Configure quorum queues for better consistency
rabbitmqctl set_policy quorum-queue ".*" '{"queue-type":"quorum"}' --apply-to queues

# Set delivery limits to prevent poison messages
rabbitmqctl set_policy delivery-limit ".*" '{"delivery-limit":10}' --apply-to queues

# Configure stream queues for high throughput
rabbitmqctl set_policy stream-queue "stream.*" '{"queue-type":"stream"}' --apply-to queues
```

## Monitoring

### Built-in Monitoring

```bash
# Node status and statistics
rabbitmqctl status
rabbitmqctl node_health_check
rabbitmqctl environment

# Queue monitoring
rabbitmqctl list_queues name messages consumers memory
rabbitmqctl list_exchanges name type
rabbitmqctl list_bindings

# Connection monitoring
rabbitmqctl list_connections peer_host peer_port state channels
rabbitmqctl list_channels connection name consumer_count messages_unacknowledged

# Cluster monitoring
rabbitmqctl cluster_status
rabbitmqctl list_cluster_nodes

# Memory and disk usage
rabbitmqctl eval 'rabbit_vm:memory().'
rabbitmqctl eval 'rabbit_disk_monitor:get_disk_free().'
```

### External Monitoring Setup

```bash
# Install RabbitMQ Exporter for Prometheus
wget https://github.com/kbudde/rabbitmq_exporter/releases/download/v1.0.0/rabbitmq_exporter-1.0.0.linux-amd64.tar.gz
tar xzf rabbitmq_exporter-*.tar.gz
sudo cp rabbitmq_exporter /usr/local/bin/

# Create monitoring user in RabbitMQ
sudo rabbitmqctl add_user prometheus PrometheusPassword123!
sudo rabbitmqctl set_user_tags prometheus monitoring

# Create systemd service
sudo tee /etc/systemd/system/rabbitmq_exporter.service <<EOF
[Unit]
Description=RabbitMQ Exporter
After=network.target

[Service]
Type=simple
User=rabbitmq
Environment=RABBIT_URL="http://prometheus:PrometheusPassword123!@localhost:15672"
ExecStart=/usr/local/bin/rabbitmq_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now rabbitmq_exporter
```

### Health Check Scripts

```bash
#!/bin/bash
# rabbitmq-health-check.sh

# Check RabbitMQ service
if ! systemctl is-active rabbitmq-server >/dev/null 2>&1; then
    echo "CRITICAL: RabbitMQ service is not running"
    exit 2
fi

# Check node health
if ! rabbitmqctl node_health_check >/dev/null 2>&1; then
    echo "CRITICAL: RabbitMQ node health check failed"
    exit 2
fi

# Check cluster status
CLUSTER_STATUS=$(rabbitmqctl cluster_status --formatter json 2>/dev/null | jq -r '.running_nodes | length')
if [ "$CLUSTER_STATUS" -lt 2 ]; then
    echo "WARNING: Less than 2 nodes running in cluster"
    exit 1
fi

# Check memory usage
MEMORY_ALARM=$(rabbitmqctl status --formatter json 2>/dev/null | jq -r '.alarms | length')
if [ "$MEMORY_ALARM" -gt 0 ]; then
    echo "WARNING: Memory alarms detected"
    exit 1
fi

# Check disk space
DISK_ALARM=$(rabbitmqctl status --formatter json 2>/dev/null | jq -r '.disk_free_alarm')
if [ "$DISK_ALARM" = "true" ]; then
    echo "WARNING: Disk space alarm active"
    exit 1
fi

# Check queue lengths
MAX_QUEUE_LENGTH=$(rabbitmqctl list_queues messages --formatter json 2>/dev/null | jq -r 'max_by(.messages).messages')
if [ "$MAX_QUEUE_LENGTH" -gt 100000 ]; then
    echo "WARNING: Queue length exceeds 100,000 messages"
    exit 1
fi

echo "OK: RabbitMQ is healthy"
exit 0
```

## 9. Backup and Restore

### Backup Procedures

```bash
#!/bin/bash
# rabbitmq-backup.sh

BACKUP_DIR="/backup/rabbitmq/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Export definitions (exchanges, queues, users, policies)
curl -u admin:SecureAdminPassword123! \
    http://localhost:15672/api/definitions \
    -o "$BACKUP_DIR/definitions.json"

# Export queue messages (if needed for small queues)
rabbitmqctl eval "
    application:load(rabbitmq_management_agent),
    rabbitmq_management_db:get_all_queues(all_vhosts).
" > "$BACKUP_DIR/queue_stats.txt"

# Backup configuration files
tar czf "$BACKUP_DIR/rabbitmq-config.tar.gz" \
    /etc/rabbitmq/ \
    --exclude='*.log' \
    --exclude='*.pid'

# Backup SSL certificates
if [ -d /etc/rabbitmq/ssl ]; then
    tar czf "$BACKUP_DIR/rabbitmq-ssl.tar.gz" /etc/rabbitmq/ssl/
fi

# Save cluster information
rabbitmqctl cluster_status > "$BACKUP_DIR/cluster_status.txt"
rabbitmqctl status > "$BACKUP_DIR/node_status.txt"

# Create manifest
echo "RabbitMQ Backup - $(date)" > "$BACKUP_DIR/backup_manifest.txt"
echo "Node: $(hostname)" >> "$BACKUP_DIR/backup_manifest.txt"
echo "Version: $(rabbitmqctl version)" >> "$BACKUP_DIR/backup_manifest.txt"

echo "Backup completed: $BACKUP_DIR"
```

### Restore Procedures

```bash
#!/bin/bash
# rabbitmq-restore.sh

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

# Stop RabbitMQ (ensure clean state)
sudo systemctl stop rabbitmq-server

# Restore configuration
sudo tar xzf "$BACKUP_DIR/rabbitmq-config.tar.gz" -C /

# Restore SSL certificates
if [ -f "$BACKUP_DIR/rabbitmq-ssl.tar.gz" ]; then
    sudo tar xzf "$BACKUP_DIR/rabbitmq-ssl.tar.gz" -C /
fi

# Start RabbitMQ
sudo systemctl start rabbitmq-server

# Wait for RabbitMQ to start
sleep 10

# Import definitions
curl -u admin:SecureAdminPassword123! \
    -X POST \
    -H "Content-Type: application/json" \
    -d @"$BACKUP_DIR/definitions.json" \
    http://localhost:15672/api/definitions

# Verify restore
rabbitmqctl list_queues
rabbitmqctl list_users

echo "Restore completed from $BACKUP_DIR"
```

### Message-Level Backup (Advanced)

```bash
#!/bin/bash
# rabbitmq-message-backup.sh

BACKUP_DIR="/backup/rabbitmq-messages/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Install shovel plugin for message transfer
rabbitmq-plugins enable rabbitmq_shovel
rabbitmq-plugins enable rabbitmq_shovel_management

# Backup messages from all queues
rabbitmqctl list_queues name --formatter json | jq -r '.[].name' | while read -r queue; do
    if [ "$queue" != "null" ]; then
        # Create shovel to backup queue
        curl -u admin:SecureAdminPassword123! -X PUT \
            "http://localhost:15672/api/parameters/shovel/%2F/backup-$queue" \
            -H "Content-Type: application/json" \
            -d "{
                \"value\": {
                    \"src-protocol\": \"amqp091\",
                    \"src-uri\": \"amqp://admin:SecureAdminPassword123!@localhost:5672/%2F\",
                    \"src-queue\": \"$queue\",
                    \"dest-protocol\": \"amqp091\",
                    \"dest-uri\": \"amqp://backup:BackupPassword123!@backup-server:5672/%2F\",
                    \"dest-queue\": \"backup-$queue\"
                }
            }"
    fi
done

echo "Message backup shovels created for all queues"
```

## 6. Troubleshooting

### Common Issues

1. **RabbitMQ won't start**:
```bash
# Check logs
sudo journalctl -u rabbitmq-server -f
sudo tail -f /var/log/rabbitmq/rabbit@$(hostname).log

# Check Erlang installation
erl -version

# Check disk space
df -h /var/lib/rabbitmq

# Check permissions
ls -la /var/lib/rabbitmq
ls -la /var/log/rabbitmq

# Reset node (last resort)
sudo rabbitmqctl stop_app
sudo rabbitmqctl reset
sudo rabbitmqctl start_app
```

2. **Cluster issues**:
```bash
# Check cluster status
rabbitmqctl cluster_status

# Check network connectivity between nodes
telnet rabbitmq-node-2 25672

# Check Erlang cookie consistency
sudo cat /var/lib/rabbitmq/.erlang.cookie

# Force cluster join
sudo rabbitmqctl stop_app
sudo rabbitmqctl join_cluster rabbit@rabbitmq-node-1
sudo rabbitmqctl start_app
```

3. **Memory/disk alarms**:
```bash
# Check alarms
rabbitmqctl status | grep alarms

# Check memory usage
rabbitmqctl eval 'rabbit_vm:memory().'

# Check disk usage
df -h /var/lib/rabbitmq

# Clear memory alarm (after fixing issue)
rabbitmqctl eval 'vm_memory_monitor:set_vm_memory_high_watermark(0.4).'
```

4. **Connection issues**:
```bash
# Check if RabbitMQ is listening
sudo ss -tlnp | grep :5672

# Test AMQP connection
rabbitmqctl eval 'rabbit_networking:tcp_listener_started(5672).'

# Check user permissions
rabbitmqctl list_user_permissions admin

# Test with management API
curl -u admin:SecureAdminPassword123! http://localhost:15672/api/overview
```

### Debug Mode

```bash
# Enable debug logging
echo 'log.file.level = debug' >> /etc/rabbitmq/rabbitmq.conf

# Enable connection logging
echo 'log.connection.level = debug' >> /etc/rabbitmq/rabbitmq.conf

# Enable channel logging  
echo 'log.channel.level = debug' >> /etc/rabbitmq/rabbitmq.conf

# Restart to apply
sudo systemctl restart rabbitmq-server

# View debug logs
sudo tail -f /var/log/rabbitmq/rabbit@$(hostname).log
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo yum check-update rabbitmq-server
sudo yum update rabbitmq-server

# Debian/Ubuntu
sudo apt update
sudo apt upgrade rabbitmq-server

# Arch Linux
sudo pacman -Syu rabbitmq

# Alpine Linux
apk update
apk upgrade rabbitmq-server

# openSUSE
sudo zypper update rabbitmq-server

# FreeBSD
pkg update
pkg upgrade rabbitmq

# Always backup before updates
./rabbitmq-backup.sh

# Test after updates
rabbitmqctl status
sudo systemctl restart rabbitmq-server
```

### Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# rabbitmq-maintenance.sh

# Rotate logs
rabbitmqctl rotate_logs

# Check node health
rabbitmqctl node_health_check

# Clean up old definitions backup
find /backup/rabbitmq -name "*.json" -mtime +30 -delete

# Optimize memory usage
rabbitmqctl eval 'erlang:garbage_collect().'

# Check and clean old message store files
rabbitmqctl eval 'rabbit_msg_store_gc:gc().'

# Check queue statistics
rabbitmqctl list_queues name messages consumers memory | \
    awk '$2 > 1000 {print "Queue " $1 " has " $2 " messages"}'

echo "RabbitMQ maintenance completed"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "*/5 * * * * /usr/local/bin/rabbitmq-health-check.sh" | sudo crontab -

# Log rotation
sudo tee /etc/logrotate.d/rabbitmq <<EOF
/var/log/rabbitmq/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        rabbitmqctl rotate_logs
    endscript
}
EOF
```

## Integration Examples

### Python (pika) Integration

```python
import pika
import ssl

# Basic connection
connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost', port=5672,
                            credentials=pika.PlainCredentials('myapp', 'SecureAppPassword123!'))
)
channel = connection.channel()

# SSL connection
ssl_context = ssl.create_default_context(cafile='/etc/rabbitmq/ssl/ca_certificate.pem')
ssl_context.check_hostname = False

ssl_connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host='localhost',
        port=5671,
        credentials=pika.PlainCredentials('myapp', 'SecureAppPassword123!'),
        ssl_options=pika.SSLOptions(ssl_context)
    )
)

# Declare queue and exchange
channel.exchange_declare(exchange='task_exchange', exchange_type='direct')
channel.queue_declare(queue='task_queue', durable=True)
channel.queue_bind(exchange='task_exchange', queue='task_queue', routing_key='task')

# Publish message
channel.basic_publish(
    exchange='task_exchange',
    routing_key='task',
    body='Hello, RabbitMQ!',
    properties=pika.BasicProperties(delivery_mode=2)  # Make message persistent
)

# Consume messages
def callback(ch, method, properties, body):
    print(f"Received: {body}")
    ch.basic_ack(delivery_tag=method.delivery_tag)

channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue='task_queue', on_message_callback=callback)
channel.start_consuming()
```

### Node.js (amqplib) Integration

```javascript
const amqp = require('amqplib');
const fs = require('fs');

// Basic connection
async function connectBasic() {
    const connection = await amqp.connect('amqp://myapp:SecureAppPassword123!@localhost:5672');
    return connection;
}

// SSL connection
async function connectSSL() {
    const connection = await amqp.connect({
        protocol: 'amqps',
        hostname: 'localhost',
        port: 5671,
        username: 'myapp',
        password: 'SecureAppPassword123!',
        ca: [fs.readFileSync('/etc/rabbitmq/ssl/ca_certificate.pem')],
        cert: fs.readFileSync('/etc/rabbitmq/ssl/client_certificate.pem'),
        key: fs.readFileSync('/etc/rabbitmq/ssl/client_key.pem')
    });
    return connection;
}

// Publisher
async function publishMessage() {
    const connection = await connectBasic();
    const channel = await connection.createChannel();
    
    const exchange = 'task_exchange';
    const routingKey = 'task';
    const message = 'Hello from Node.js!';
    
    await channel.assertExchange(exchange, 'direct', { durable: true });
    await channel.publish(exchange, routingKey, Buffer.from(message), { persistent: true });
    
    console.log('Message sent');
    await channel.close();
    await connection.close();
}

// Consumer
async function consumeMessages() {
    const connection = await connectBasic();
    const channel = await connection.createChannel();
    
    const queue = 'task_queue';
    
    await channel.assertQueue(queue, { durable: true });
    await channel.prefetch(1);
    
    console.log('Waiting for messages...');
    
    channel.consume(queue, async (message) => {
        if (message) {
            console.log('Received:', message.content.toString());
            // Process message
            channel.ack(message);
        }
    });
}
```

### Java (Spring AMQP) Integration

```java
// Configuration
@Configuration
@EnableRabbit
public class RabbitConfig {
    
    @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory factory = new CachingConnectionFactory("localhost");
        factory.setPort(5672);
        factory.setUsername("myapp");
        factory.setPassword("SecureAppPassword123!");
        factory.setVirtualHost("/");
        return factory;
    }
    
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMandatory(true);
        return template;
    }
    
    @Bean
    public DirectExchange taskExchange() {
        return new DirectExchange("task_exchange", true, false);
    }
    
    @Bean
    public Queue taskQueue() {
        return QueueBuilder.durable("task_queue").build();
    }
    
    @Bean
    public Binding taskBinding() {
        return BindingBuilder.bind(taskQueue()).to(taskExchange()).with("task");
    }
}

// Producer
@Service
public class MessageProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void sendMessage(String message) {
        rabbitTemplate.convertAndSend("task_exchange", "task", message);
    }
}

// Consumer
@Service
public class MessageConsumer {
    
    @RabbitListener(queues = "task_queue")
    public void receiveMessage(String message) {
        System.out.println("Received: " + message);
        // Process message
    }
}
```

### Go (amqp091-go) Integration

```go
package main

import (
    "log"
    "github.com/rabbitmq/amqp091-go"
)

func connectRabbitMQ() (*amqp091.Connection, error) {
    return amqp091.Dial("amqp://myapp:SecureAppPassword123!@localhost:5672/")
}

func publishMessage(message string) error {
    conn, err := connectRabbitMQ()
    if err != nil {
        return err
    }
    defer conn.Close()

    ch, err := conn.Channel()
    if err != nil {
        return err
    }
    defer ch.Close()

    // Declare exchange
    err = ch.ExchangeDeclare(
        "task_exchange",
        "direct",
        true,  // durable
        false, // auto-deleted
        false, // internal
        false, // no-wait
        nil,   // arguments
    )
    if err != nil {
        return err
    }

    // Declare queue
    _, err = ch.QueueDeclare(
        "task_queue",
        true,  // durable
        false, // delete when unused
        false, // exclusive
        false, // no-wait
        nil,   // arguments
    )
    if err != nil {
        return err
    }

    // Publish message
    return ch.Publish(
        "task_exchange",
        "task",
        false, // mandatory
        false, // immediate
        amqp091.Publishing{
            ContentType:  "text/plain",
            Body:         []byte(message),
            DeliveryMode: amqp091.Persistent,
        },
    )
}

func consumeMessages() error {
    conn, err := connectRabbitMQ()
    if err != nil {
        return err
    }
    defer conn.Close()

    ch, err := conn.Channel()
    if err != nil {
        return err
    }
    defer ch.Close()

    msgs, err := ch.Consume(
        "task_queue",
        "",    // consumer
        false, // auto-ack
        false, // exclusive
        false, // no-local
        false, // no-wait
        nil,   // args
    )
    if err != nil {
        return err
    }

    forever := make(chan bool)

    go func() {
        for d := range msgs {
            log.Printf("Received: %s", d.Body)
            // Process message
            d.Ack(false)
        }
    }()

    log.Printf("Waiting for messages...")
    <-forever
    return nil
}
```

## Additional Resources

- [Official RabbitMQ Documentation](https://www.rabbitmq.com/documentation.html)
- [RabbitMQ Tutorials](https://www.rabbitmq.com/getstarted.html)
- [RabbitMQ Management Plugin](https://www.rabbitmq.com/management.html)
- [RabbitMQ Clustering Guide](https://www.rabbitmq.com/clustering.html)
- [RabbitMQ High Availability](https://www.rabbitmq.com/ha.html)
- [AMQP 0-9-1 Protocol Reference](https://www.rabbitmq.com/amqp-0-9-1-reference.html)
- [RabbitMQ Community](https://www.rabbitmq.com/community.html)
- [RabbitMQ GitHub Repository](https://github.com/rabbitmq/rabbitmq-server)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.