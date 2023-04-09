
# openssl-hook

A helper library for embedding rats-tls into a programs without recompiling it from source code, with the help of `LD_PRELOAD`. 

## How to use

We have tested it with `curl` and `nginx`.

### nginx

In a TD VM, we launch a simple nginx server which holds a default page, with https enabled.

Note that rats-tls should be compiled in `tdx` mode.

```sh
# create a nginx configuration file, and save it as ~/nginx.conf
cat <<EOF > ~/nginx.conf
daemon off;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256;

    server {
        listen 1234 ssl;
        server_name your_domain.com;

        ssl_certificate /root/cert.pem;
        ssl_certificate_key /root/key.pem;

        # rest of your server configuration
    }
}
EOF

# launch the nginx server
LD_PRELOAD=/usr/share/rats-tls/samples/libopenssl-hook_lib.so nginx -c ~/nginx.conf
```

### curl

Here is the client side, no TEE is required, so you can compile rats-tls with `host` mode.

```sh
LD_PRELOAD=/usr/share/rats-tls/samples/libopenssl-hook_lib.so curl -vvvvv --resolve RATS-TLS:1234:<nginx_ip_address>  https://RATS-TLS:1234/
```

> In the current implementation, the CN field is always `RATS-TLS`. However, the curl would compare `CN` field in cert with hostname in url. Here we use `--resolve RATS-TLS:1234:<nginx_ip_address>` to bypass the check from curl. 

## Debug

You can use `gdb` to to debug this library.

```sh
gdb --args env LD_PRELOAD=/usr/share/rats-tls/samples/libopenssl-hook_lib.so <your-target-app>
```

## TODO

1. Compile-time hook.
    `LD_PRELOAD` relies on the capability of `ld.so`, which does not work in SGX mode, since all object are statically linked. however, it might be possible to accomplish this with some hacks on the commandline flags of `ld` during linking.

2. Add a executable target.
    It would be better to have a tiny helper executable to launch (i.e. `openssl-hook <COMMAND [ARGS]...>`) instead of set env `LD_PRELOAD` manually.
    Also, all configurations are currently hard-coded, and we have to provide a way to configure rats-tls.

