if [ -z "$1" ]; then
  echo "Missing domain name.  Usage: docker-build.sh <domain.name>"
else
  docker volume create moongem-content
  docker volume create moongem-certs
  docker build -t moongem  --build-arg DOMAIN_NAME=$1 .
fi
