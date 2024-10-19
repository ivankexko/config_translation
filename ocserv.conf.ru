################################################################################
# ПРИМЕЧАНИЕ: Не изменяйте этот файл для настройки ocserv. Добавьте новые
# директивы в /etc/ocserv/ocserv.conf.local, и они будут включены в конфигурацию
# ocserv
################################################################################

# Метод аутентификации пользователя. Может быть установлен несколько раз, и в
# этом случае все должно пройти успешно.
# Варианты: certificate, pam. 
#auth = "certificate"
#auth = "pam"

# Параметр gid-min используется параметром auto-select-group для выбора
# минимального идентификатора группы.
#auth = "pam[gid-min=1000]"

# Для простого варианта требуется указать файл паролей, содержащий записи
# следующего формата.
# "username:groupname:encoded-password"
# В каждой строке должна быть указана одна запись, а для генерации паролей можно
# использовать "ocpasswd".
auth = "|AUTH|"

# Баннер, который будет отображаться на клиентах после подключения
banner = "Welcome to OpenWRT"

# Баннер, который будет отображаться на клиентах перед подключением
#pre-login-banner = "Welcome"

#isolate-workers = true

# Если у сервера динамический DNS-адрес (который может измениться), следует
# установить его в значение true, чтобы запросить у клиента повторное разрешение
# при повторном подключении.
listen-host-is-dyndns = |DYNDNS|

# Используйте listen-host, чтобы ограничиться определенными IP-адресами или
# IP-адресами указанного имени хоста.
#listen-host = [IP|HOSTNAME]

# Ограничить количество клиентов.
# Используйте ноль для неограниченного количества.
#max-clients = 1024
max-clients = |MAX_CLIENTS|

# Установите ограничение на количество входящих подключений до одного клиента
# каждые X миллисекунд (X - это указанное значение) по мере увеличения второго
# периода ожидания. Это повышает устойчивость сервера (и предотвращает сбои
# соединения) при нескольких одновременных подключениях. Установите нулевое
# значение, чтобы не было ограничений.
rate-limit-ms = 100

# Ограничьте количество одинаковых клиентов (т.е. пользователей, подключающихся
# несколько раз).
# Используйте ноль для неограниченного количества.
max-same-clients = |MAX_SAME|

# Номер порта TCP и UDP
tcp-port = |PORT|
|UDP|udp-port = |UDP_PORT|

# Время отчета о состоянии. Количество секунд, по истечении которых каждый
# рабочий процесс будет сообщать статистику своего использования (количество
# переданных байт и т.д.). Это полезно, если используется учет, подобный radius.
#stats-report-time = 360

# Время сброса статистики. Будет сброшена статистика за период времени,
# сохраняемый основным/вторым процессами. Это статистика, отображаемая командой
# "occtl show stats". За день: 86400, за неделю: 604800
# Это никак не связано со временем составления отчета о состоянии.
server-stats-reset-time = 604800

# Подержания активности через указанный период в секундах.
keepalive = 32400

# Обнаружение мертвого peer за считанные секунды.
dpd = |DPD|

# Обнаружение мертвого peer для мобильных клиентов. Требования должны быть
# намного выше, чтобы такие клиенты не слишком часто просыпались из-за сообщений
# DPD для экономии заряда батареи
# (клиенты, отправляющие X-AnyConnect-Identifier-DeviceType).
mobile-dpd = 1800

# Если используется протокол DTLS, а UDP-трафик не поступает в течение данного
# количества секунд, попробовать вместо этого отправить будущий трафик по
# TCP-соединению, чтобы попытаться разбудить клиента в случае, если есть NAT и
# трансляция UDP была удалена. Если этот параметр не установлен, этот механизм
# восстановления использоваться не будет.
switch-to-tcp-timeout = 25

# Обнаружение MTU (DPD должен быть включен)
try-mtu-discovery = false

#### Ключ и сертификаты сервера
# Ключом может быть файл или любой URL-адрес, поддерживаемый GnuTLS (например,
# tpmkey:uuid=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx;storage=user or
# pkcs11:object=my-vpn-key;object-type=private)
#
# Может быть несколько пар сертификатов и ключей, и каждый ключ должен
# соответствовать предыдущему сертификату.
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem

# Параметры Diffie-Hellman. Требуется только в том случае, если вам требуется
# поддержка наборов шифров DHE (по умолчанию этот сервер поддерживает ECDHE).
# Может быть сгенерирован с помощью:
# certtool --generate-dh-params --outfile /path/to/dh.pem
#dh-params = /path/to/dh.pem

# Если у вас есть сертификат от центра сертификации, предоставляющего службу
# OCSP, вы можете предоставить новый ответ о статусе OCSP в рамках подтверждения
# TLS. Это предотвратит независимое подключение клиента к серверу OCSP.
# Вы можете периодически обновлять этот ответ с помощью:
# ocsptool --ask --load-cert=your_cert --load-issuer=your_ca --outfile response
# Убедитесь, что вы заменили следующий файл атомарным способом.
#ocsp-response = /path/to/ocsp.der

# В случае использования ключей PKCS #11 или доверенного платформенного модуля,
# PIN-коды должны быть доступны в файлах. Файл srk-pin применим только к ключам
# доверенного платформенного модуля и является корневым ключом хранилища.
#pin-file = /path/to/pin.txt
#srk-pin-file = /path/to/srkpin.txt

# Центр сертификации, который будет использоваться для проверки клиентских 
# сертификатов (открытых ключей), если установлена проверка подлинности по
# сертификату.
#ca-cert = /etc/ocserv/ca.pem

# Идентификатор объекта, который будет использоваться для считывания
# идентификатора пользователя в клиентском сертификате. Идентификатор объекта
# должен быть частью DN сертификата.
# Полезными OID являются:
# CN = 2.5.4.3, UID = 0.9.2342.19200300.100.1.1
#cert-user-oid = 0.9.2342.19200300.100.1.1

# Идентификатор объекта, который будет использоваться для определения группы
# пользователей в клиентском сертификате. Идентификатор объекта должен быть
# частью DN сертификата. Полезными OID являются:
#  OU (organizational unit) = 2.5.4.11 
#cert-group-oid = 2.5.4.11

# Список аннулированных сертификатов, выданных вышеуказанным "ca-cert".
#crl = /etc/ocserv/crl.pem

# Раскомментируйте это, чтобы включить согласование сжатия (LZS, LZ4).
|COMPRESSION|compression = true

# Строка приоритета GnuTLS
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"

# Для обеспечения идеальной прямой секретности (PFS) на главном канале.
#tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-RSA"

# Время (в секундах), в течение которого клиенту разрешается оставаться на связи
# до прохождения аутентификации.
auth-timeout = 240

# Время (в секундах), в течение которого клиент может находиться в режиме
# ожидания (без трафика) перед отключением.
# Снимите флажок отключить.
#idle-timeout = 1200

# Время (в секундах), в течение которого мобильному клиенту разрешается 
# оставаться в режиме ожидания (без трафика) перед отключением.
# Снимите флажок отключить.
#mobile-idle-timeout = 2400

# Время (в секундах), в течение которого клиенту не разрешается повторно
# подключаться после неудачной попытки аутентификации.
min-reauth-time = 360

# Блокировка клиентов в ocserv работает по системе начисления баллов. IP-адреса,
# которые набирают количество баллов, превышающее указанное в настройках,
# блокируются на минимальное время авторизации. По умолчанию за неверную попытку
# ввода пароля начисляется 10 баллов, за сообщение KKDCP - 1 балл, а за
# подключение - 1 балл. Обратите внимание, что из-за различий в используемых
# процессах подсчет баллов не будет точным в режиме реального времени.
#
# Запрет Score не может быть надежно использован при получении прокси-соединений
# локально с HTTP-сервера (т.е. когда используется функция listen-clear-file).
#
# Установите значение "ноль" для отключения.
max-ban-score = 80

# Время (в секундах), в течение которого все оценки, сохраненные для клиента,
# сбрасываются.
ban-reset-time = 1200

# На случай, если вы захотите изменить значения по умолчанию.
#ban-points-wrong-password = 10
#ban-points-connection = 1
#ban-points-kkdcp = 1

# Время ожидания файлов cookie (в секундах)
# Как только клиент проходит аутентификацию, ему предоставляется файл cookie, с
# помощью которого он может повторно подключиться. Этот файл cookie будет
# признан недействительным, если не будет использован в течение этого времени
# ожидания. Этот файл cookie остается действительным в течение времени
# подключения пользователя, а после отключения пользователя он остается активным
# в течение этого периода времени. Эта настройка должна обеспечивать разумный
# промежуток времени для перемещения между различными сетями.
cookie-timeout = 300

# Если эта функция включена (не рекомендуется), файлы cookie будут оставаться
# действительными даже после того, как пользователь отключится вручную, и до
# истечения срока их действия. Это может улучшить роуминг с некоторыми
# неработающими клиентами.
#persistent-cookies = true

# Запрещен ли роуминг, т.е. если это значение равно true, файл cookie ограничен
# одним IP-адресом и не может быть повторно использован с другого IP-адреса.
deny-roaming = false

# Время повторного ввода (в секундах) ocserv будет запрашивать у клиента
# периодическое обновление ключей по истечении этого времени. Установите нулевое
# значение для отключения (обратите внимание, что некоторые клиенты выходят из
# строя, если rekey отключен).
rekey-time = 172800

# Метод повторного подключения
# Допустимые параметры: ssl, new-tunnel
#  ssl: Выполнит эффективное повторное подключение к каналу, обеспечивая
#    бесперебойное соединение во время повторного подключения.
# new-tunnel: Даст указание клиенту отменить и восстановить канал. Используйте
#    эту опцию только в том случае, если у подключающихся клиентов возникают
#    проблемы с опцией ssl.
rekey-method = ssl

# Скрипт, вызываемый при подключении клиента и получении IP-адреса
# Следующие параметры передаются в среду выполнения скрипта:
# REASON - событие, может быть "подключение" или "отключение";
# USERNAME - имя пользовтеля;
# GROUPNAME - имя группы;
# HOSTNAME - имя хоста, выбранное клиентом; 
# DEVICE - устройство;
# IP_REAL - реальный IP клиента;
# IP_LOCAL - локальный IP в PtP-соединении;
# IP_REMOTE - VPN-IP клиента;
# ID - уникальный цифровой идентификатор.

# Эти скрипты не нужны, если вы настроили интерфейс для всех устройств vpn+.
#connect-script = /usr/bin/ocserv-script
#disconnect-script = /usr/bin/ocserv-script

# UTMP
use-utmp = false

################################################################################
# Whether to enable support for the occtl tool (i.e., either through D-BUS,
# or via a unix socket).
use-occtl = true

# socket file used for IPC with occtl. You only need to set that,
# if you use more than a single servers.
occtl-socket-file = /var/run/occtl.socket

# PID file. It can be overriden in the command line.
pid-file = /var/run/ocserv.pid

# The default server directory. Does not require any devices present.
chroot-dir = /var/lib/ocserv

# socket file used for IPC, will be appended with .PID
# It must be accessible within the chroot environment (if any)
#socket-file = /var/run/ocserv-socket
socket-file = ocserv-socket

# The user the worker processes will be run as. It should be
# unique (no other services run as this user).
run-as-user = ocserv
run-as-group = ocserv

# Set the protocol-defined priority (SO_PRIORITY) for packets to
# be sent. That is a number from 0 to 6 with 0 being the lowest
# priority. Alternatively this can be used to set the IP Type-
# Of-Service, by setting it to a hexadecimal number (e.g., 0x20).
# This can be set per user/group or globally.
#net-priority = 3

# Set the VPN worker process into a specific cgroup. This is Linux
# specific and can be set per user/group or globally.
#cgroup = "cpuset,cpu:test"

#
# Network settings
#

# The name of the tun device
device = vpns

# Whether the generated IPs will be predictable, i.e., IP stays the
# same for the same user when possible.
predictable-ips = |PREDICTABLE_IPS|

# The default domain to be advertised
|ENABLE_DEFAULT_DOMAIN|default-domain = |DEFAULT_DOMAIN|

# The pool of addresses that leases will be given from.
ipv4-network = |IPV4ADDR|
ipv4-netmask = |NETMASK|

# The advertized DNS server. Use multiple lines for
# multiple servers.
# dns = fc00::4be0
#dns = 192.168.1.2

# The NBNS server (if any)
#nbns = 192.168.1.3

# The IPv6 subnet that leases will be given from.
|ENABLE_IPV6|ipv6-network = |IPV6ADDR|

# The domains over which the provided DNS should be used. Use
# multiple lines for multiple domains.
|ENABLE_SPLIT_DNS|split-dns = |DEFAULT_DOMAIN|

# Prior to leasing any IP from the pool ping it to verify that
# it is not in use by another (unrelated to this server) host.
ping-leases = |PING_LEASES|

# Whether to tunnel all DNS queries via the VPN. This is the default
# when a default route is set.
#tunnel-all-dns = true

# Unset to assign the default MTU of the device
# mtu = 

# Unset to enable bandwidth restrictions (in bytes/sec). The
# setting here is global, but can also be set per user or per group.
#rx-data-per-sec = 40000
#tx-data-per-sec = 40000

# The number of packets (of MTU size) that are available in
# the output buffer. The default is low to improve latency.
# Setting it higher will improve throughput.
#output-buffer = 10

# Routes to be forwarded to the client. If you need the
# client to forward routes to the server, you may use the 
# config-per-user/group or even connect and disconnect scripts.
#
# To set the server as the default gateway for the client just
# comment out all routes from the server.
#route = 192.168.1.0/255.255.255.0
#route = 192.168.5.0/255.255.255.0
#route = fef4:db8:1000:1001::/64

# Configuration files that will be applied per user connection or
# per group. Each file name on these directories must match the username
# or the groupname.
# The options allowed in the configuration files are dns, nbns,
#  ipv?-network, ipv4-netmask, ipv6-prefix, rx/tx-per-sec, iroute, route,
#  net-priority and cgroup.
#
# Note that the 'iroute' option allows to add routes on the server
# based on a user or group. The syntax depends on the input accepted
# by the commands route-add-cmd and route-del-cmd (see below).

config-per-user = /etc/ocserv/config-per-user/
config-per-group = /etc/ocserv/config-per-group/

# When config-per-xxx is specified and there is no group or user that
# matches, then utilize the following configuration.

#default-user-config = /etc/ocserv/defaults/user.conf
#default-group-config = /etc/ocserv/defaults/group.conf

# Groups that a client is allowed to select from.
# A client may belong in multiple groups, and in certain use-cases
# it is needed to switch between them. For these cases the client can
# select prior to authentication. Add multiple entries for multiple groups.
#select-group = group1
#select-group = group2[My group 2]
#select-group = tost[The tost group]

# The name of the group that if selected it would allow to use
# the assigned by default group.
#default-select-group = DEFAULT

# Instead of specifying manually all the allowed groups, you may instruct
# ocserv to scan all available groups and include the full list. That
# option is only functional on plain authentication.
#auto-select-group = true

# The system command to use to setup a route. %{R} will be replaced with the
# route/mask and %{D} with the (tun) device.
#
# The following example is from linux systems. %{R} should be something
# like 192.168.2.0/24

#route-add-cmd = "/usr/sbin/ip route add %{R} dev %{D}"
#route-del-cmd = "/usr/sbin/ip route delete %{R} dev %{D}"

route-add-cmd = "/sbin/route add -net %{RI} dev %{D}"
route-del-cmd = "/sbin/route del -net %{RI} dev %{D}"

# This option allows to forward a proxy. The special strings '%{U}'
# and '%{G}', if present will be replaced by the username and group name.
#proxy-url = http://example.com/
#proxy-url = http://example.com/%{U}/%{G}/hello

#
# The following options are for (experimental) AnyConnect client 
# compatibility. 

# Client profile xml. A sample file exists in doc/profile.xml.
# This file must be accessible from inside the worker's chroot. 
# It is not used by the openconnect client.
#user-profile = profile.xml

# Binary files that may be downloaded by the CISCO client. Must
# be within any chroot environment.
#binary-files = /path/to/binaries

# Unless set to false it is required for clients to present their
# certificate even if they are authenticating via a previously granted
# cookie and complete their authentication in the same TCP connection.
# Legacy CISCO clients do not do that, and thus this option should be 
# set for them.
cisco-client-compat = |CISCO_COMPAT|

#Advanced options

# Option to allow sending arbitrary custom headers to the client after
# authentication and prior to VPN tunnel establishment.
#custom-header = "X-My-Header: hi there"

expose-iroutes = true

################################################################################
# Log Level. Ocserv sends the logging messages to standard error
# as well as the system log. The log level can be overridden in the
# command line with the -d option. All messages at the configured
# level and lower will be displayed.
# Supported levels (default 0):
#   0 default (Same as basic)
#   1 basic
#   2 info
#   3 debug
#   4 http
#   8 sensitive
#   9 TLS
log-level = 3

# Эта опция активирует протокол обхода X-CSTP-Client-Bypass-Protocol (по
# умолчанию отключен). Если сервер не настроил пул адресов IPv6 или IPv4,
# включение этой опции позволит клиенту обойти сервер по этому IP-протоколу.
# В настоящее время эта опция доступна только клиентам Anyconnect.
client-bypass-protocol = false

# Следующие опции относятся к маскировке сервера (скрытому сервису)

# Эта опция позволяет вам включить функцию маскировки ocserv, которая делает его
# похожим на веб-сервер для посторонних лиц. При включенном "камуфляже"
# подключение к VPN может быть установлено только в том случае, если клиент
# указал определенную "секретную строку" в URL-адресе подключения, например:
# https://example.com/?mysecretkey
# в противном случае сервер будет возвращать HTTP-ошибку для всех запросов.
camouflage = false

# Префикс URL-адреса, который может быть установлен на клиенте (после знака "?")
# для прохождения проверки маскировки, например, в случае "mysecretkey"
# URL-адрес сервера на клиенте должен быть похож на:
# https://example.com/?mysecretkey
camouflage_secret = "mysecretkey"

# Определяет область (запрос браузера) для HTTP-аутентификации. Если область не
# задана, сервер вернет ошибку 404 Not found вместо 401 Unauthorized. Лучше
# изменить значение по умолчанию, чтобы избежать обнаружения отпечатков пальцев.
camouflage_realm = "Restricted Content"

# HTTP headers
included-http-headers = Strict-Transport-Security: max-age=31536000 ; includeSubDomains
included-http-headers = X-Frame-Options: deny
included-http-headers = X-Content-Type-Options: nosniff
included-http-headers = Content-Security-Policy: default-src 'none'
included-http-headers = X-Permitted-Cross-Domain-Policies: none
included-http-headers = Referrer-Policy: no-referrer
included-http-headers = Clear-Site-Data: "cache","cookies","storage"
included-http-headers = Cross-Origin-Embedder-Policy: require-corp
included-http-headers = Cross-Origin-Opener-Policy: same-origin
included-http-headers = Cross-Origin-Resource-Policy: same-origin
included-http-headers = X-XSS-Protection: 0
included-http-headers = Pragma: no-cache
included-http-headers = Cache-control: no-store, no-cache
