FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install

COPY dashboard/tsconfig.json dashboard/tsconfig.node.json dashboard/vite.config.ts dashboard/index.html ./
COPY dashboard/postcss.config.js dashboard/tailwind.config.js ./

COPY dashboard/src ./src

RUN npm run build

FROM nginx:alpine AS runner

RUN apk add --no-cache curl

COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /usr/src/app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
