FROM docker:dind

COPY cross/linux/amd64/notary /usr/local/bin/notary

WORKDIR /root

RUN mkdir -p .notary/certs && mkdir -p .docker/trust

VOLUME [ "/root/.docker/trust" ]

COPY fixtures/notary-server.key fixtures/notary-server.crt fixtures/root-ca.crt /root/.notary/certs/

COPY fixtures/sandbox-config.json /root/.notary/config.json