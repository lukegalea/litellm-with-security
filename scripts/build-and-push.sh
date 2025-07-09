#!/bin/bash

# LiteLLM Custom Image Build and Push Script
# ==========================================
# This script builds and pushes custom LiteLLM Docker images to GitHub Container Registry
# following the same methodology as the official LiteLLM project
# 
# Usage:
#   ./scripts/build-and-push.sh [options]
#
# Options:
#   -u, --username    GitHub username (default: lukegalea)
#   -t, --tag         Image tag (default: latest)
#   -r, --registry    Docker registry (default: ghcr.io)
#   -p, --push        Push to registry after build (default: true)
#   -h, --help        Show this help message

set -e  # Exit on any error

# Default configuration (matching official builds)
GITHUB_USERNAME="${GITHUB_USERNAME:-lukegalea}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io}"
PUSH_IMAGE="${PUSH_IMAGE:-true}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
LiteLLM Custom Image Build and Push Script

Usage: $0 [options]

Options:
    -u, --username    GitHub username (default: $GITHUB_USERNAME)
    -t, --tag         Image tag (default: $IMAGE_TAG)
    -r, --registry    Docker registry (default: $DOCKER_REGISTRY)
    -p, --push        Push to registry after build (default: $PUSH_IMAGE)
    -h, --help        Show this help message

Environment Variables:
    GITHUB_TOKEN      GitHub Personal Access Token (required for pushing)
    GITHUB_USERNAME   GitHub username
    IMAGE_TAG         Docker image tag
    DOCKER_REGISTRY   Docker registry URL
    PLATFORMS         Build platforms (default: linux/amd64,linux/arm64)

Examples:
    # Build and push with defaults
    $0

    # Build only (no push)
    $0 --push false

    # Build with custom tag
    $0 --tag v1.0.0

    # Build for specific user
    $0 --username myusername --tag dev
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)
            GITHUB_USERNAME="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -r|--registry)
            DOCKER_REGISTRY="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Build configuration
IMAGE_NAME="litellm"
FULL_IMAGE_NAME="${DOCKER_REGISTRY}/${GITHUB_USERNAME}/${IMAGE_NAME}"

# Display configuration
log_info "Build Configuration:"
echo "  Registry: $DOCKER_REGISTRY"
echo "  Username: $GITHUB_USERNAME"
echo "  Image: $IMAGE_NAME"
echo "  Tag: $IMAGE_TAG"
echo "  Full name: $FULL_IMAGE_NAME:$IMAGE_TAG"
echo "  Platforms: $PLATFORMS"
echo "  Push: $PUSH_IMAGE"
echo ""

# Check required tools
log_info "Checking required tools..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker buildx version &> /dev/null; then
    log_error "Docker Buildx is not available"
    exit 1
fi

log_success "All required tools are available"

# Authenticate with GitHub Container Registry
if [[ "$PUSH_IMAGE" == "true" ]]; then
    log_info "Authenticating with GitHub Container Registry..."
    
    if [[ -z "$GITHUB_TOKEN" ]]; then
        log_error "GITHUB_TOKEN environment variable is required for pushing to GHCR"
        log_info "Please set GITHUB_TOKEN with a Personal Access Token that has 'write:packages' permission"
        exit 1
    fi
    
    echo "$GITHUB_TOKEN" | docker login "$DOCKER_REGISTRY" -u "$GITHUB_USERNAME" --password-stdin
    if [[ $? -eq 0 ]]; then
        log_success "Successfully authenticated with $DOCKER_REGISTRY"
    else
        log_error "Failed to authenticate with $DOCKER_REGISTRY"
        exit 1
    fi
fi

# Set up Docker Buildx (matching official LiteLLM approach)
log_info "Setting up Docker Buildx..."
docker buildx create --use --name=multiarch --driver=docker-container --bootstrap 2>/dev/null || docker buildx use multiarch

# Build the image (following official LiteLLM methodology)
log_info "Building LiteLLM image..."

# Build command matching the official workflow
if [[ "$PUSH_IMAGE" == "true" ]]; then
    log_info "Building and pushing to registry..."
    docker buildx build \
        --platform "$PLATFORMS" \
        --tag "$FULL_IMAGE_NAME:$IMAGE_TAG" \
        --tag "$FULL_IMAGE_NAME:latest" \
        --build-arg LITELLM_BUILD_IMAGE=cgr.dev/chainguard/python:latest-dev \
        --build-arg LITELLM_RUNTIME_IMAGE=cgr.dev/chainguard/python:latest-dev \
        --push \
        .
else
    log_info "Building locally (no push)..."
    docker buildx build \
        --platform "linux/amd64" \
        --tag "$FULL_IMAGE_NAME:$IMAGE_TAG" \
        --tag "$FULL_IMAGE_NAME:latest" \
        --build-arg LITELLM_BUILD_IMAGE=cgr.dev/chainguard/python:latest-dev \
        --build-arg LITELLM_RUNTIME_IMAGE=cgr.dev/chainguard/python:latest-dev \
        --load \
        .
fi

if [[ $? -eq 0 ]]; then
    log_success "Successfully built LiteLLM image: $FULL_IMAGE_NAME:$IMAGE_TAG"
    
    if [[ "$PUSH_IMAGE" == "true" ]]; then
        log_success "Image pushed to registry: $DOCKER_REGISTRY"
        log_info "You can now use this image in other projects:"
        echo "  image: $FULL_IMAGE_NAME:$IMAGE_TAG"
        echo ""
        log_info "To use in docker-compose.yml:"
        echo "  services:"
        echo "    litellm:"
        echo "      image: $FULL_IMAGE_NAME:$IMAGE_TAG"
    else
        log_success "Image built locally (not pushed)"
    fi
else
    log_error "Failed to build LiteLLM image"
    exit 1
fi

# Show image info
log_info "Image information:"
if [[ "$PUSH_IMAGE" == "false" ]]; then
    docker images "$FULL_IMAGE_NAME:$IMAGE_TAG"
fi

log_success "Build process completed successfully!" 