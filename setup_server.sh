#!/bin/bash

# apt-get install sudo nginx rustc


##### /etc/sudoers

#proxyuser ALL=NOPASSWD: /bin/systemctl reload nginx.service

##### sshd_config
#### https://askubuntu.com/questions/48129/how-to-create-a-restricted-ssh-user-for-port-forwarding#50000
#Match User proxyuser
#   #AllowTcpForwarding yes
#   #X11Forwarding no
#   #PermitTunnel no
#   #GatewayPorts no
#   AllowAgentForwarding no
#   PermitOpen localhost:*
#   ForceCommand echo 'Only NextBox BackwardProxy'


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
