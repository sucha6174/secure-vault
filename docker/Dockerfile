FROM node:20-alpine

# Install build dependencies and utilities
RUN apk add --no-cache python3 make g++ curl

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install dependencies deterministically
RUN npm ci

# Copy application source code
COPY . .

# Ensure entrypoint has execution permission
RUN chmod +x docker/entrypoint.sh

# Pre-compile smart contracts during build
RUN npx hardhat compile

# Run deployer entrypoint
CMD ["sh", "./docker/entrypoint.sh"]
