FROM golang:1.26-alpine AS build
ENV GOMAXPROCS=2 GOMEMLIMIT=750MiB
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -p 1 -trimpath -o /airlock-gateway .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 gateway
COPY --from=build /airlock-gateway /usr/local/bin/airlock-gateway
USER 10001
EXPOSE 8443
ENTRYPOINT ["airlock-gateway"]
