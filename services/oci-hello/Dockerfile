FROM --platform=linux/amd64 docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4

COPY index.html healthz /www/
ENTRYPOINT ["/bin/httpd", "-f", "-p", "80", "-h", "/www"]
