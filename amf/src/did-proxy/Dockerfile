################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################

# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download || true

# Copy source code
COPY . .

# Download dependencies (if go.sum doesn't exist)
RUN go mod tidy

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o did-proxy .

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -g '' didproxy

# Create directories
RUN mkdir -p /usr/local/etc/oai/keys && \
    chown -R didproxy:didproxy /usr/local/etc/oai

# Copy binary from builder
COPY --from=builder /app/did-proxy /app/did-proxy

# Copy default configuration
COPY etc/config_with_bcf.yaml /usr/local/etc/oai/config.yaml

# Set ownership
RUN chown -R didproxy:didproxy /app

# Switch to non-root user
USER didproxy

# Expose DID Proxy port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8090/health || exit 1

# Run the service
ENTRYPOINT ["/app/did-proxy"]
CMD ["-config", "/usr/local/etc/oai/config.yaml", "-keypath", "/usr/local/etc/oai/keys"]
