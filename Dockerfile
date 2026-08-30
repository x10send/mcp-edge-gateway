FROM node:26-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:26-alpine AS runtime

ENV NODE_ENV=production
RUN apk upgrade --no-cache
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev \
  && npm cache clean --force \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --from=build /app/dist ./dist

COPY start.sh ./start.sh

USER node

EXPOSE 8788
EXPOSE 8789
CMD ["/bin/sh", "start.sh"]
