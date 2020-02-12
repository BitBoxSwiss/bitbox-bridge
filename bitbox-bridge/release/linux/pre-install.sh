getent group bitbox >/dev/null || groupadd -r bitbox
getent passwd bitbox >/dev/null || useradd -r -g bitbox -d /var -s /bin/false -c "Shiftcrypto User" bitbox
