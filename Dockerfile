# 1. BUILD STAGE: Install dependencies and compile TypeScript
FROM node:24-alpine AS builder

WORKDIR /app
COPY package*.json ./
# Use npm ci for deterministic installs
RUN npm ci

COPY . .
RUN npm run build

# 2. RUN STAGE: Keep only production dependencies and run the app
FROM node:24-alpine

WORKDIR /app
COPY package*.json ./
# Install only prod dependencies
RUN npm ci --omit=dev && npm cache clean --force

# Copy only the compiled output from builder
COPY --from=builder /app/dist ./dist

# Use the built-in non-root 'node' user for security
USER node

EXPOSE 8080

CMD ["node", "dist/main.js"]
