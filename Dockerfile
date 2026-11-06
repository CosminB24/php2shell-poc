FROM php:8.4.26-apache
COPY php.ini /usr/local/etc/php/php.ini
COPY webroot/ /var/www/html/
