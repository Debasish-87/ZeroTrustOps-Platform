FROM python:3.11-slim

WORKDIR /app

# System dependencies
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl wget git docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go + build sectl
RUN wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

COPY sectl/ /tmp/sectl-src/
RUN cd /tmp/sectl-src \
    && go mod tidy \
    && go mod download \
    && go build -ldflags "-s -w" -o /usr/local/bin/sectl . \
    && rm -rf /tmp/sectl-src \
    && echo "✅ sectl: $(/usr/local/bin/sectl --version)"

# Python dependencies
COPY platform/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# API source
COPY platform/api/ .

# Workspace for cloned repos
RUN mkdir -p /workspace

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
