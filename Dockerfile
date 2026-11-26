# Container image for running passkeytool serve on Cloud Run or any other
# container platform. Data lives in /tmp, so it resets with the container.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /passkeytool .

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /passkeytool /passkeytool
ENV PASSKEYS_DATA=/tmp/passkeys-data.json
ENTRYPOINT ["/passkeytool"]
CMD ["serve", "-aaguids", "/tmp/aaguid.json"]
