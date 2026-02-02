FROM golang:1.25-alpine3.23 AS builder

COPY go.mod go.sum ./

RUN go mod download

COPY . /app
WORKDIR /app

# Toggle CGO based on your app requirement. CGO_ENABLED=1 for enabling CGO
RUN CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -o /app/main *.go
# Use below if using vendor
# RUN CGO_ENABLED=0 go build -mod=vendor -ldflags '-s -w -extldflags "-static"' -o /app/appbin *.go

FROM alpine:3.23
ARG VERSION=dev
LABEL MAINTAINER="Author waynelau15045@gmail.com"
LABEL org.opencontainers.image.source=https://github.com/wheynelau/claude-gitleaks
LABEL org.opencontainers.image.version=${VERSION}

# Following commands are for installing CA certs (for proper functioning of HTTPS and other TLS)
RUN apk --update add ca-certificates && \
    rm -rf /var/cache/apk/*

# Add new user 'appuser'
RUN adduser -D appuser
USER appuser

COPY --from=builder /app/main /home/appuser/main

WORKDIR /home/appuser/

# Since running as a non-root user, port bindings < 1024 is not possible
# 8000 for HTTP; 8443 for HTTPS;
EXPOSE 8000

ENTRYPOINT ["./main"]