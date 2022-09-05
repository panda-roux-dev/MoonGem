# install runtime dependencies
FROM alpine:latest AS base
RUN apk --no-cache add lua5.4-libs openssl libevent bash file pcre2

# install required build dependencies
FROM base AS build
RUN apk --no-cache add \
  lua5.4-dev pcre2-dev openssl-dev libevent-dev \
  file-dev cmake gcc make musl-dev
WORKDIR /build/
COPY . .

# build the service
RUN cmake . && make

FROM base AS publish

# use environment variables to configure various
# aspects of the service
ENV MG_KEY_NAME=key.pem
ENV MG_CERT_NAME=cert.pem
ENV MG_BEFORE_SCRIPT=before.lua
ENV MG_AFTER_SCRIPT=after.lua
ENV MG_ERROR_SCRIPT=error.lua
ENV MG_PORT=1965

# the service will access files via mounted file
# volumes
VOLUME /gemini
VOLUME /gemini/public

# create the service user account
RUN adduser -D -H mg && mkdir -p /gemini && chown -R mg:mg /gemini

# copy the compiled binary to the /app/ directory
WORKDIR /app/
COPY --from=build --chown=mg:mg /build/moongem .
COPY ./container/start.sh .

# run the service
USER mg:mg
EXPOSE ${MG_PORT}
ENTRYPOINT ["/bin/bash", "-c", "/app/start.sh"]
