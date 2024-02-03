FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY static static
COPY html html
COPY go go
RUN go build -o /bin/server ./go

FROM alpine AS final

WORKDIR /app

COPY --from=builder /bin/server ./server

CMD ["./server"]