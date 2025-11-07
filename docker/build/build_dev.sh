source ./image_names.sh
docker build -t $DEVELOPMENT_IMAGE -f ../../Dockerfile.test ../..
