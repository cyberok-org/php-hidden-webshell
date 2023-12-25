FROM ubuntu
LABEL maintainer="CyberOK"
RUN apt-get update && apt-get install -y tzdata
ENV TZ=Europe/Moscow
RUN apt-get update && apt-get install -y wget libapr1-dev  libaprutil1-dev build-essential
RUN apt-get update && apt-get install -y libpcre3-dev libxml2-dev sqlite3 libsqlite3-dev libonig-dev pkg-config zlib1g-dev
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.53.tar.gz
RUN tar xvzf httpd-2.4.53.tar.gz
RUN wget https://www.php.net/distributions/php-7.4.33.tar.gz
RUN tar xvzf php-7.4.33.tar.gz
WORKDIR /httpd-2.4.53
RUN ./configure --prefix=/usr/local/apache2 && make && make install
WORKDIR /php-7.4.33
RUN ./configure --with-apxs2=/usr/local/apache2/bin/apxs --with-mysqli --with-pdo-mysql --enable-mbregex --enable-mbstring
RUN make && make install
COPY etc/php.ini /usr/local/lib/
COPY etc/httpd.conf /usr/local/apache2/conf/
COPY etc/poc.php /usr/local/apache2/htdocs/
COPY etc/test.php /usr/local/apache2/htdocs/
RUN chown -R daemon:daemon /usr/local/apache2/htdocs/
RUN chmod 755 /usr/local/apache2/htdocs/poc.php
WORKDIR /var/www/html
EXPOSE 80
CMD ["/usr/local/apache2/bin/apachectl", "-DFOREGROUND"]
