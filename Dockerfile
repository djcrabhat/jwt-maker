# syntax=docker/dockerfile:1

FROM golang:1.18-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o /workflow-jwt-creator

EXPOSE 8080
EXPOSE 8081


CMD [ "/workflow-jwt-creator" ]