FROM zaproxy/zap-bare:latest

USER root
RUN apk add --no-cache socat
COPY --chown=zap:zap entrypoint.sh /zap/entrypoint.sh
RUN chmod +x /zap/entrypoint.sh

USER zap
ENTRYPOINT ["/zap/entrypoint.sh"]
