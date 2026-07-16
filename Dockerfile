FROM node:20-alpine

WORKDIR /app

# Copy just the manifest files first so Docker can cache this layer -
# rebuilds only re-run npm install when dependencies actually change,
# not on every source edit.
COPY package*.json ./
RUN npm install --production

COPY src ./src
COPY public ./public

# The node:alpine image ships a built-in unprivileged "node" user.
# Running as it instead of root limits the blast radius if the
# container is ever compromised - cheap defense-in-depth.
USER node

EXPOSE 3000

CMD ["node", "src/server.js"]
