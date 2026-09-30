FROM node:24-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY server.js ./
COPY src ./src
COPY public ./public
RUN mkdir -p /var/data/sentinel && chown -R node:node /app /var/data/sentinel

USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 DATA_DIR=/var/data/sentinel
EXPOSE 3000
CMD ["node", "server.js"]
