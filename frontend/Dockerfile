# STUCK frontend — Vite static build served by nginx.
# Build:  docker build -t stuck-frontend ./frontend
# Run:    docker run -p 3000:3000 stuck-frontend

# Exact tags + multi-platform digests are updated deliberately with the locks.
FROM node:24.14.1-alpine3.23@sha256:8510330d3eb72c804231a834b1a8ebb55cb3796c3e4431297a24d246b8add4d5 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.29.8-alpine3.23@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS runner
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 3000
