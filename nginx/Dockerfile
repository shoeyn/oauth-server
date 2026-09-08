FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:9000/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
