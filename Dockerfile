# syntax=docker/dockerfile:1
FROM golang:1.17-alpine
COPY . /go/src/authz-server
WORKDIR /go/src/authz-server
RUN go get authzserver
RUN go install
ENTRYPOINT ["/go/bin/authzserver"]