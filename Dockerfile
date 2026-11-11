FROM node:22.5-alpine

WORKDIR /app

COPY moneyflow/package*.json ./
RUN npm ci

COPY moneyflow/ .

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

EXPOSE 3000

CMD ["node", "server.js"]
