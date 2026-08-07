FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080

# Use 127.0.0.1, not localhost: nginx's `listen 8080` binds IPv4 only, and
# this image's /etc/hosts resolves localhost to ::1 first, so wget against
# "localhost" gets connection-refused even though the app is up and serving.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
