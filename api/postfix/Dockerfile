FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y postfix mailutils && apt-get clean

RUN echo "postfix postfix/mailname string faithsafe.net" | debconf-set-selections
RUN echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

RUN postconf -e 'myhostname = faithsafe.net' \
    && postconf -e 'mydomain = faithsafe.net' \
    && postconf -e 'myorigin = $mydomain' \
    && postconf -e 'inet_interfaces = all' \
    && postconf -e 'inet_protocols = ipv4' \
    && postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost' \
    && postconf -e 'mynetworks = 127.0.0.0/8, [::1]/128' \
    && postconf -e 'relayhost ='

EXPOSE 25

CMD service postfix start && tail -f /var/log/mail.log
