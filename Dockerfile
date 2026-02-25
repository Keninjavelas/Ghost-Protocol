FROM python:3.11-slim

WORKDIR /app

# System deps for asyncssh & psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev openssh-client && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate SSH host key if not mounted
RUN mkdir -p config && \
    [ -f config/ssh_host_rsa_key ] || \
    ssh-keygen -t rsa -b 4096 -N "" -f config/ssh_host_rsa_key

EXPOSE 2222 8000

CMD ["python", "-m", "gateway.ssh_server"]
