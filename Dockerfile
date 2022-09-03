# syntax=docker/dockerfile:1

FROM golang:1.18-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o /workflow-jwt-creator

EXPOSE 8000
EXPOSE 8001

CMD [ "/workflow-jwt-creator" ]