# vpn-project
## Create a CA-cert + public CA-key

```bash
openssl req -x509 -newkey rsa:1048 -keyout ca.key.pem -out ca.cert.pem -nodes -days 365
```

## Create a CSR

```bash
openssl req -out user.csr.csr -new -newkey rsa:1048 -nodes -keyout user.private.key
```

## Sign CSR

```bash
openssl x509 -req -days 365 -in user.csr.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out user.pem
```

## Test Certificate
```bash
openssl x509 -in server-certificate.pem -text -noout
```

##Run the VPN
```bash
java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der
```

```bash
java ForwardClient --handshakehost=localhost  --handshakeport=2206 --proxyport=12345 --targethost=localhost --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der 
```

```bash
ncat -l 6789
```

```bash
ncat localhost 12345
```