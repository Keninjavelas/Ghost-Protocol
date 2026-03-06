FROM python:3.11-slim

WORKDIR /app

# System deps for asyncssh & psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev openssh-client && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps -r requirements.txt || true
RUN pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir reportlab asyncssh structlog pyyaml pydantic pydantic-settings sqlalchemy asyncpg psycopg2-binary redis aioredis uvicorn fastapi starlette docker paramiko httpx aiohttp cryptography bcrypt pynacl scikit-learn numpy scipy torch tiktoken openai

COPY . .

# Generate SSH host key if not mounted
RUN mkdir -p config && \
    [ -f config/ssh_host_rsa_key ] || \
    ssh-keygen -t rsa -b 4096 -N "" -f config/ssh_host_rsa_key

EXPOSE 2222 8000

CMD ["python", "-m", "dashboard.backend.main"]
