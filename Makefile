IMAGE_NAME=stakejoy-api
REPO=registry.digitalocean.com/stakejoy
IMAGE_FULL=${REPO}/${IMAGE_NAME}:latest

build:
	@docker build . -t ${IMAGE_NAME}

push:
	@docker tag ${IMAGE_NAME} ${IMAGE_FULL}
	@docker push ${IMAGE_FULL}

deploy: build push