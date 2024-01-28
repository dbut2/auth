FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY html/ html/
COPY static/ static/

COPY *.go ./
COPY auth auth
COPY cookie cookie
COPY crypto crypto
COPY models models
COPY providers providers
RUN go build -o /bin/server .

FROM alpine

WORKDIR /app

COPY --from=builder /bin/server ./server

CMD ["./server"]