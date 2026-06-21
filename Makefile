.PHONY: help build-ai build-edge build-all docker-up docker-down k8s-deploy k8s-delete clean

help:
	@echo "AI-Driven IoT IDS - Deployment Commands"
	@echo ""
	@echo "Docker Commands:"
	@echo "  make build-ai        - Build AI service Docker image"
	@echo "  make build-edge      - Build edge gateway Docker image"
	@echo "  make build-all       - Build all Docker images"
	@echo "  make docker-up       - Start local development environment"
	@echo "  make docker-down     - Stop local development environment"
	@echo ""
	@echo "Kubernetes Commands:"
	@echo "  make k8s-deploy      - Deploy to Kubernetes cluster"
	@echo "  make k8s-delete      - Remove from Kubernetes cluster"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean           - Clean up build artifacts"

# Docker build commands
build-ai:
	docker build -f Dockerfile.ai-service -t iot-ids/ai-service:latest .

build-edge:
	docker build -f Dockerfile.edge-gateway -t iot-ids/edge-gateway:latest .

build-all: build-ai build-edge

# Docker Compose commands
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Kubernetes commands
k8s-deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/configmaps.yaml
	kubectl apply -f k8s/persistent-volumes.yaml
	kubectl apply -f k8s/elasticsearch-statefulset.yaml
	kubectl apply -f k8s/ai-service-deployment.yaml
	kubectl apply -f k8s/edge-gateway-daemonset.yaml
	kubectl apply -f k8s/network-policies.yaml
	kubectl apply -f k8s/ingress.yaml

k8s-delete:
	kubectl delete -f k8s/ingress.yaml
	kubectl delete -f k8s/network-policies.yaml
	kubectl delete -f k8s/edge-gateway-daemonset.yaml
	kubectl delete -f k8s/ai-service-deployment.yaml
	kubectl delete -f k8s/elasticsearch-statefulset.yaml
	kubectl delete -f k8s/persistent-volumes.yaml
	kubectl delete -f k8s/configmaps.yaml
	kubectl delete -f k8s/namespace.yaml

k8s-status:
	kubectl get all -n iot-ids

# Clean up
clean:
	docker-compose down -v
	rm -rf __pycache__ .pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
