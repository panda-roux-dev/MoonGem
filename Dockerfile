#--------------------------------
# Stage 1: build

FROM alpine:latest AS build
RUN mkdir -p /usr/src/bin /certs
ARG DOMAIN_NAME

# install build prerequisites
RUN apk add --no-cache file-dev openssl-dev build-base gcc make cmake openssl libmagic extra-cmake-modules

# download and install Lua
RUN wget -q -O - https://www.lua.org/ftp/lua-5.4.3.tar.gz | tar zxf -
RUN make -j$(grep -c ^processor /proc/cpuinfo) -C lua-5.4.3 && make -C lua-5.4.3 install

# copy and build application source
WORKDIR /usr/src
COPY . .
RUN cmake -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/usr/src/bin . && make -j$(grep -c ^processor /proc/cpuinfo) all

# generate certificates and copy them to /certs
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=$DOMAIN_NAME"
RUN cp *.pem /certs/


#--------------------------------
# Stage 2: deploy

FROM alpine:latest AS deploy
RUN mkdir -p /usr/src/app /gemini /certs

# install runtime prerequisites
RUN apk add --no-cache libmagic

# create a lesser-privileged user for running MoonGem and 
# give it ownership of the certificates we generated
RUN addgroup -S moongem && adduser -S moongem -G moongem

# copy artifacts from build image
WORKDIR /usr/src/app
COPY --chown=moongem --from=build /usr/src/bin/* .

# create a volume mount-point for storing certificates
VOLUME /certs
COPY --chown=moongem --from=build /certs/*.pem /certs/

# create a volume mount-point for storing served content
VOLUME /gemini

# use the new user account
USER moongem
EXPOSE 1965
CMD ["./moongem", "/certs/cert.pem", "/certs/key.pem", "/gemini"]
