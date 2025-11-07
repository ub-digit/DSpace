source ./image_names.sh
docker build -t $PRODUCTION_IMAGE -f ../../Dockerfile ../..
