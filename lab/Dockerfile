# INTENTIONALLY INSECURE Dockerfile (for Scout's code.dockerfile lint).
# Problems on purpose: unpinned base, runs as root, secret baked into ENV.
FROM node:latest
WORKDIR /app
COPY . .
RUN npm install && npm run build
ENV API_KEY="l4b-baked-into-image-00xplz"
EXPOSE 4000
CMD ["npm", "start"]
