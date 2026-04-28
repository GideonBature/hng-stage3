#!/bin/sh
# Rendered by the nginx:alpine docker-entrypoint before nginx starts.
# Substitutes only the env-driven placeholders (DASHBOARD_DOMAIN, DOCKER_GATEWAY_IP)
# so that nginx's own $variable references in the template are left untouched.
set -eu

envsubst '${DASHBOARD_DOMAIN} ${DOCKER_GATEWAY_IP}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf
