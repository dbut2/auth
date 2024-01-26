FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY *.go ./
COPY login.html login.html

RUN go build -o /bin/server .

FROM alpine

WORKDIR /app

COPY --from=builder /bin/server ./server

CMD ["./server"]