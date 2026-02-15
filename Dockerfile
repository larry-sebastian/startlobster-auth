FROM node:22-alpine
WORKDIR /app
COPY server.js login.html ./
EXPOSE 3000
CMD ["node", "server.js"]
