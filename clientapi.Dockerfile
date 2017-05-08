FROM golang:1.7.5-alpine

RUN apk add --update git gcc libc-dev ca-certificates && rm -rf /var/cache/apk/*

ENV NOTARY_PKG github.com/docker/notary

COPY . /go/src/$NOTARY_PKG

WORKDIR /go/src/$NOTARY_PKG
RUN go install \
    $NOTARY_PKG/cmd/clientapi

EXPOSE 4449

ENTRYPOINT [ "clientapi" ]
CMD [ "-config", "fixtures/clientapi-server-config.toml" ]
