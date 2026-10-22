# Multi-stage build. No ENV is set anywhere in this image on purpose: a baked-in
# value (NODE_ENV, APP_SECRETS, etc.) is the documented cause of the wrong
# environment in production. All config is injected at runtime via APP_SECRETS.

FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY --from=builder /app/server.js ./server.js
COPY --from=builder /app/public ./public
EXPOSE 3000
USER node
CMD ["node", "server.js"]
