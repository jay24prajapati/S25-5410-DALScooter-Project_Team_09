# Build stage
FROM node:18-alpine AS build

WORKDIR /app

# Install dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY yarn.lock* ./

# Install dependencies
RUN if [ -f yarn.lock ]; then yarn install --frozen-lockfile; else npm ci; fi

# Copy source and build
COPY .. .

# Set build environment
ENV NODE_ENV=production
ENV GENERATE_SOURCEMAP=false

# Build the app
RUN npm run build

RUN ls -la /app/ && \
    if [ -d "dist" ]; then echo "Found dist directory"; ls -la dist/; fi && \
    if [ -d "build" ]; then echo "Found build directory"; ls -la build/; fi

# Production stage
FROM nginx:1.25-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Remove default nginx files
RUN rm -rf /usr/share/nginx/html/*

# Copy dist directory (most likely for Vite)
COPY --from=build /app/dist /usr/share/nginx/html

# Create minimal nginx config
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    location /health { \
        return 200 "healthy"; \
        add_header Content-Type text/plain; \
    } \
}' > /etc/nginx/conf.d/default.conf

RUN rm /etc/nginx/conf.d/default.conf.dpkg-dist 2>/dev/null || true

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]