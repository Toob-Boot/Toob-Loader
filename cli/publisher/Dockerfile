FROM alpine:3.19

# Install dependencies: docker-cli, bash, curl
RUN apk add --no-cache docker-cli bash curl jq

# Install webhook (adnanh/webhook)
RUN apk add --no-cache webhook

# Install nektos/act
RUN curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | bash

# Copy configuration and entrypoint
COPY hooks.json /etc/webhook/hooks.json
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Webhook default port
EXPOSE 9000

# Start webhook daemon with -template flag to allow reading secrets from environment
CMD ["webhook", "-hooks", "/etc/webhook/hooks.json", "-template", "-verbose"]
