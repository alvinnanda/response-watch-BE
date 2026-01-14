# Variables
PROJECT_ID=response-watch
REGION=asia-southeast1
REPO_NAME=responsewatch-backend
IMAGE_NAME=responsewatch-api
SERVICE_NAME=responsewatch-api
IMAGE_PATH=$(REGION)-docker.pkg.dev/$(PROJECT_ID)/$(REPO_NAME)/$(IMAGE_NAME):latest

.PHONY: build push deploy all logs status health help

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build   Build the Docker image for linux/amd64"
	@echo "  push    Push the Docker image to Artifact Registry"
	@echo "  deploy  Deploy the service to Cloud Run"
	@echo "  all     Build, push, and deploy"
	@echo "  logs    Stream logs from Cloud Run"
	@echo "  status  Show Cloud Run service status"
	@echo "  health  Check service health via curl"

build:
	docker build --platform linux/amd64 --provenance=false -t $(IMAGE_NAME):latest .

push:
	docker tag $(IMAGE_NAME):latest $(IMAGE_PATH)
	gcloud auth configure-docker $(REGION)-docker.pkg.dev --quiet
	docker push $(IMAGE_PATH)

deploy:
	gcloud run deploy $(SERVICE_NAME) \
		--image $(IMAGE_PATH) \
		--platform managed \
		--region $(REGION) \
		--project $(PROJECT_ID) \
		--env-vars-file env.yaml

all: build push deploy

logs:
	gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$(SERVICE_NAME)" --limit 20 --project $(PROJECT_ID)

status:
	gcloud run services describe $(SERVICE_NAME) --region $(REGION) --project $(PROJECT_ID)

health:
	@SERVICE_URL=$$(gcloud run services describe $(SERVICE_NAME) --region $(REGION) --project $(PROJECT_ID) --format='value(status.url)'); \
	echo "Checking health at $$SERVICE_URL/api/health"; \
	curl -s -f $$SERVICE_URL/api/health || echo "Health check failed"
