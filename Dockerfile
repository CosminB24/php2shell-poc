FROM php:8.4.26-apache

LABEL org.opencontainers.image.title="php2shell-lab" \
      org.opencontainers.image.description="Educational lab for php2shell PoC — do not expose outside localhost" \
      org.opencontainers.image.source="https://github.com/CosminB24/php2shell-poc" \
      org.opencontainers.image.licenses="educational"

# Lab PHP config — must not be changed without recalibrating stage-3 offsets.
COPY php.ini /usr/local/etc/php/php.ini
COPY webroot/ /var/www/html/
