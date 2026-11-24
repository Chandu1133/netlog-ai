# Deploying NetLog AI on AWS EC2 Free Tier (Docker Compose)

This guide walks through deploying **NetLog AI** (FastAPI + MySQL 8) on an AWS EC2 Free Tier
instance (`t2.micro` or `t3.micro`) running Ubuntu 24.04 LTS using Docker Compose.

## 1. Launch an EC2 Instance

1. Open the **AWS EC2 Console** and click **Launch instance**.
2. Configure the instance:
   - **Name**: `netlog-ai-prod`
   - **AMI**: Ubuntu Server 24.04 LTS (HVM, SSD, 64-bit x86)
   - **Instance type**: `t2.micro` or `t3.micro` (Free Tier eligible, 1 GiB RAM)
   - **Key pair**: Select or create an `.pem` SSH key pair.
   - **Storage**: 20 GiB `gp3` (within the 30 GiB Free Tier limit).
3. Configure **Security Group** inbound rules:
   - **SSH (TCP 22)**: Restrict source to **My IP**.
   - **HTTP (TCP 80)**: `0.0.0.0/0` (if using Nginx reverse proxy) or **Custom TCP 8000** for direct access during evaluation.
   - **HTTPS (TCP 443)**: `0.0.0.0/0` (recommended with Let's Encrypt).
   - **Do NOT expose TCP 3306 (MySQL)** publicly.
4. Click **Launch instance**.

## 2. Connect & Configure Swap (Recommended for 1 GiB RAM)

MySQL 8 + scikit-learn benefit from a 2 GiB swap file on a 1 GiB Free Tier instance:

```bash
chmod 400 ~/Downloads/netlog-key.pem
ssh -i ~/Downloads/netlog-key.pem ubuntu@<EC2_PUBLIC_IP>

# Create a 2 GiB swap file
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## 3. Install Docker & Docker Compose Plugin

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker
```

## 4. Clone the Repository & Configure Environment

```bash
git clone https://github.com/<your-username>/netlog-ai.git
cd netlog-ai
cp .env.example .env
```

Generate strong secrets and update `.env`:

```bash
# Generate random API key and DB password
python3 -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('MYSQL_PASSWORD=' + secrets.token_urlsafe(24))"
```

Edit `.env` (`nano .env`) and set at minimum:

```env
APP_ENV=production
LOG_LEVEL=INFO
MYSQL_ROOT_PASSWORD=<strong-root-password>
MYSQL_DATABASE=netlog_ai
MYSQL_USER=netlog
MYSQL_PASSWORD=<strong-db-password>
API_KEY=<strong-api-key>

# Keep LLM_PROVIDER=mock for zero-cost demo, or switch to openai with a real key:
LLM_PROVIDER=mock
LLM_API_KEY=
```

> **Security Tip**: In `docker-compose.yml`, remove or comment out the `ports: ["3306:3306"]`
> mapping under `mysql` in production so MySQL is reachable only inside the Docker network.

## 5. Build and Start the Stack

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f api
```

On startup, the API container automatically runs `alembic upgrade head` against MySQL 8 and
starts Uvicorn on port `8000`.

## 6. Verify Health & Seed Sample Data

```bash
curl -s http://localhost:8000/health
```

Expected response:

```json
{"status":"ok","database":"connected","llm_provider":"mock","version":"1.0.0"}
```

Optionally generate and upload a synthetic dataset to populate the dashboard immediately:

```bash
docker compose exec api python scripts/generate_logs.py --output-dir /tmp/demo
docker compose exec api sh -c 'curl -s -X POST "http://localhost:8000/logs/upload?run_analysis=true" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@/tmp/demo/synthetic_server.log"'
```

Visit `http://<EC2_PUBLIC_IP>:8000/` for the dashboard and `http://<EC2_PUBLIC_IP>:8000/docs`
for OpenAPI documentation.

## 7. Optional: Add HTTPS with Nginx & Certbot

If you point a domain (e.g., `netlog.example.com`) to `<EC2_PUBLIC_IP>`:

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo tee /etc/nginx/sites-available/netlog-ai > /dev/null <<'EOF'
server {
    listen 80;
    server_name netlog.example.com;
    client_max_body_size 15M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/netlog-ai /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d netlog.example.com
```

## 8. Operations & Maintenance

- **Update deployment**: `git pull && docker compose up -d --build`
- **Database backup**:
  ```bash
  docker compose exec mysql mysqldump -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" > backup_$(date +%F).sql
  ```
- **Inspect logs**: `docker compose logs --tail=200 api`
