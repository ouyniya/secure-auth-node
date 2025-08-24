# Stage 1: Build
FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies dev + prod
COPY package*.json ./
RUN npm ci 

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build application creating /dist (compile TypeScript → JavaScript)
RUN npm run build

# ✅ ลบ devDependencies ทิ้ง เหลือเฉพาะ production
RUN npm prune --production


# Stage 2: Production
FROM node:22-alpine

# Install security updates
RUN apk update && apk upgrade && apk add --no-cache dumb-init

# Create non-root user (nodeuser)
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodeuser -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodeuser:nodejs /app/dist ./dist
COPY --from=builder --chown=nodeuser:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodeuser:nodejs /app/package.json ./
COPY --from=builder --chown=nodeuser:nodejs /app/prisma ./prisma

# Copy entrypoint script
COPY --chown=nodeuser:nodejs entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh

# Create logs directory
RUN mkdir -p logs && chown nodeuser:nodejs logs

USER nodeuser

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]