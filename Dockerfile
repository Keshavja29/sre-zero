# Node.js Lightweight Production Container for SRE-Zero
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies
RUN npm install --omit=dev

# Copy application source code
COPY . .

# Set default port
ENV PORT=8080
EXPOSE 8080

# Start server
CMD ["node", "server.js"]
