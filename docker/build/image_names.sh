if test "$1" = ""
then
  source ./.env
else
  GUB_DSPACE_VERSION=$1
fi

PRODUCTION_IMAGE=docker.ub.gu.se/dspace:dspace-8_x-${GUB_DSPACE_VERSION}
DEVELOPMENT_IMAGE=docker.ub.gu.se/dspace:dspace-8_x-dev # No versioned image to save space, needs docker compose pull

