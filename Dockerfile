# Builder
FROM alpine AS nodpi-builder

WORKDIR /app

# Download latest release source code
RUN apk add --no-cache git && \
    git clone https://github.com/GVCoder09/NoDPI . && \
    mv src/main.py src/nodpi && \
    rm -rf .git

# Preparing run script
RUN echo '#!/bin/sh'                                              > ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo '# For Docker HEALTHCHECK'                              >> ./entrypoint.sh && \
    echo 'if [ "$1" = "healthcheck" ]; then'                     >> ./entrypoint.sh && \
    echo '  port=$(netstat -l | egrep -o ":[0-9]{1,}")'          >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo '  check_url="https://youtube.com"'                     >> ./entrypoint.sh && \
    echo '  [ -n "$2" ] && check_url="$2"'                       >> ./entrypoint.sh && \
    echo '  nodpi_proxy="http://127.0.0.1$port"'                 >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo '  https_proxy="$nodpi_proxy" curl -s "$check_url"'     >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo '  exit $?'                                             >> ./entrypoint.sh && \
    echo 'fi'                                                    >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo 'workdir="/app"'                                        >> ./entrypoint.sh && \
    echo 'blacklist_file="$workdir/blacklist.txt"'               >> ./entrypoint.sh && \
    echo 'nodpi="$workdir/src/nodpi"'                            >> ./entrypoint.sh && \
    echo 'blacklists_dir="/blacklists"'                          >> ./entrypoint.sh && \
    echo 'tmp_file="/tmp/blacklist.txt"'                         >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo 'if [ -d "$blacklists_dir" ]; then'                     >> ./entrypoint.sh && \
    echo '  cat "$blacklists_dir"/* > "$tmp_file" 2>/dev/null'   >> ./entrypoint.sh && \
    echo '  if [ -f "$tmp_file" ] && [ -s "$tmp_file" ]; then'   >> ./entrypoint.sh && \
    echo '    blacklist_file="$tmp_file"'                        >> ./entrypoint.sh && \
    echo '  fi'                                                  >> ./entrypoint.sh && \
    echo 'fi'                                                    >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo 'BLACKLIST="--blacklist $blacklist_file"'               >> ./entrypoint.sh && \
    echo 'HOST="--host 0.0.0.0"'                                 >> ./entrypoint.sh && \
    echo 'for arg in $*; do'                                     >> ./entrypoint.sh && \
    echo '  [ "$arg" = '--blacklist' ] && BLACKLIST=""'          >> ./entrypoint.sh && \
    echo '  [ "$arg" = '--no_blacklist' ] && BLACKLIST=""'       >> ./entrypoint.sh && \
    echo '  [ "$arg" = '--host' ] && HOST=""'                    >> ./entrypoint.sh && \
    echo 'done'                                                  >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    echo 'python3 "$nodpi" "$@" $HOST $BLACKLIST'                >> ./entrypoint.sh && \
    echo                                                         >> ./entrypoint.sh && \
    chmod +x ./entrypoint.sh

# App runner
FROM python:3-alpine AS app

RUN apk add --no-cache curl && \
    adduser -u 1000 -D -h /app -s /sbin/nologin nodpi

COPY --from=nodpi-builder /app /app

VOLUME [/blacklists]

USER nodpi

HEALTHCHECK       \
    --interval=5s \
    --timeout=3s  \
    --retries=2   \
    CMD /app/entrypoint.sh healthcheck https://youtube.com

EXPOSE 8881

ENTRYPOINT ["/app/entrypoint.sh"]
