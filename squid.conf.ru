################################################################################
# Рекомендуемая минимальная конфигурация:

################################################################################
# Пример правила, разрешающего доступ из ваших локальных сетей.

#-------------------------------------------------------------------------------
# Адаптируйте список ваших (внутренних) IP-сетей, из которых должен быть
# разрешен просмотр веб-страниц.
acl localnet src 0.0.0.1-0.255.255.255 # RFC 1122 "эта" сеть (LAN)
acl localnet src 10.0.0.0/8            # RFC 1918 локальная частная сеть (LAN)
acl localnet src 100.64.0.0/10         # RFC 6598 общее адресное пространство (CGN)
acl localnet src 169.254.0.0/16        # RFC 3927 link-local (напрямую подключаемые) компьютеры
acl localnet src 172.16.0.0/12         # RFC 1918 локальная частная сеть (LAN)
acl localnet src 192.168.0.0/16	       # RFC 1918 локальная частная сеть (LAN)
acl localnet src fc00::/7              # RFC 4193 диапазон локальной частной сети
acl localnet src fe80::/10             # RFC 4291 link-local (напрямую подключаемые) компьютеры

#-------------------------------------------------------------------------------
# Порты удаленных хостов, к которым разрешается подключение через прокси
acl SSL_ports port 443		# https (ssl/tls)
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# незарегистрированные порты
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http

#-------------------------------------------------------------------------------
# Резрешенные методы подключения
acl CONNECT method CONNECT

################################################################################
# Рекомендуемая конфигурация минимальных разрешений доступа:

#-------------------------------------------------------------------------------
# Запрещать запросы к ко всем, кроме описанных портов
http_access deny !Safe_ports

#-------------------------------------------------------------------------------
# Запретить CONNECT к портам, отличным от защищенных SSL
http_access deny CONNECT !SSL_ports

#-------------------------------------------------------------------------------
# Разрешить доступ к cachemgr только с локального хостинга
http_access allow localhost manager
http_access deny manager

#-------------------------------------------------------------------------------
# Мы настоятельно рекомендуем раскомментировать следующее, чтобы защитить
# невинные веб-приложения, работающие на прокси-сервере, которые думают, что
# единственный, кто может получить доступ к службам на "localhost", - это
# локальный пользователь.
#http_access deny to_localhost

################################################################################
# ВВЕДИТЕ ЗДЕСЬ СВОИ СОБСТВЕННЫЕ ПРАВИЛА, ЧТОБЫ РАЗРЕШИТЬ ДОСТУП ВАШИМ КЛИЕНТАМ.

#-------------------------------------------------------------------------------
# Пример правила, разрешающего доступ из ваших локальных сетей. Измените
# localnet в разделе ACL, чтобы в нем был указан список ваших (внутренних)
# IP-сетей, из которых должен быть разрешен просмотр веб-страниц
http_access allow localnet
http_access allow localhost

#-------------------------------------------------------------------------------
# И, наконец, запретить всем остальным доступ к этому прокси-серверу
http_access deny all

#-------------------------------------------------------------------------------
# Раскомментируйте и измените следующее, чтобы добавить каталог дискового кэша.
#cache_dir ufs /usr/local/squid/var/cache/squid 100 16 256

################################################################################
# Добавьте любую из ваших собственных записей refresh_pattern поверх этих.
#-------------------------------------------------------------------------------
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern .		0	20%	4320

#-------------------------------------------------------------------------------
# Пользователь Squid
cache_effective_user squid

################################################################################
# Журналы лучше всего использовать только для отладки, так как они могут стать
# очень большими

#-------------------------------------------------------------------------------
access_log none  # daemon:/tmp/squid_access.log
cache_log /dev/null  # /tmp/squid_cache.log

################################################################################
# Автоматически подставляемые параметры
# (последняя строка должна быть пустой)


