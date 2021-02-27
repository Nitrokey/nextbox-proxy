#!/bin/bash

# apt-get install sudo nginx rustc

#Cmnd_Alias MYAPP_CMNDS = /bin/systemctl reload nginx
#proxyuser ALL=(ALL) NOPASSWD: MYAPP_CMNDS


# mkdir -p /srv/nextbox-proxy/sites


# nginx.conf
# include /src/nextbox-proxy/sites/*;


# touch /srv/nextbox-proxy/registered_keys


# create ~/cloudflare.ini
# pip3 install -U certbot cloudflare certbot_dns_cloudflare
# run certbot
# $ certbot certonly \
#  --dns-cloudflare \
#  --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
#  -d example.com
#
#  certificate at: /etc/letsencrypt/live/nextbox.link/
