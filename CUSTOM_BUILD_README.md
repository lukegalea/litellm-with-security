# Custom LiteLLM Docker Build Guide

## Quick Start

This repository has been configured to build and push custom LiteLLM Docker images to GitHub Container Registry (GHCR), avoiding conflicts with local services.

### Prerequisites

1. **GitHub Personal Access Token**: Create a token with `write:packages` permission
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Create a token with `write:packages` scope
   - Save it securely (you'll need it for building)

2. **Docker**: Ensure Docker is running on your system

### Port Configuration

This setup uses non-conflicting ports:
- **LiteLLM**: Host port `4001` → Container port `4000`
- **PostgreSQL**: Host port `5433` → Container port `5432`  
- **Prometheus**: Host port `9091` → Container port `9090`

### Building and Pushing Your Custom Image

#### Method 1: Using the Build Script (Recommended)

```bash
# Set your GitHub token
export GITHUB_TOKEN="your_github_personal_access_token"

# Build and push with defaults (lukegalea/litellm:latest)
./scripts/build-and-push.sh

# Build with custom tag
./scripts/build-and-push.sh --tag v1.0.0

# Build only (don't push)
./scripts/build-and-push.sh --push false

# Build for different user
./scripts/build-and-push.sh --username yourusername
```

#### Alternative: Direct Docker Commands

If you prefer to run the commands manually (matching the official LiteLLM approach):

```bash
# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u lukegalea --password-stdin

# Set up buildx for multi-platform builds
docker buildx create --use --name=multiarch --driver=docker-container --bootstrap

# Build and push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/lukegalea/litellm:latest \
  --push \
  .
```

### Using Your Custom Image

#### In This Project

The `docker-compose.yml` is already configured to use your custom image:

```bash
# Start with your custom image
docker-compose up -d
```

Access LiteLLM at: http://localhost:4001

#### In Other Projects

Reference your custom image in other `docker-compose.yml` files:

```yaml
services:
  litellm:
    image: ghcr.io/lukegalea/litellm:latest
    ports:
      - "4000:4000"
    environment:
      DATABASE_URL: "your_database_url"
```

### Image Variants

The build script creates these image tags:
- `ghcr.io/lukegalea/litellm:latest` - Always points to the most recent build
- `ghcr.io/lukegalea/litellm:your-tag` - Specific version when using `--tag`

### Troubleshooting

#### Authentication Issues
```bash
# Test GHCR authentication
echo $GITHUB_TOKEN | docker login ghcr.io -u lukegalea --password-stdin
```

#### Build Issues
```bash
# Clean buildx cache
docker buildx prune -f

# Remove and recreate buildx builder
docker buildx rm multiarch
docker buildx create --use --name=multiarch --driver=docker-container --bootstrap

# Clean Docker system (if needed)
docker system prune -f
```

#### Port Conflicts
If you still have port conflicts, modify the ports in `docker-compose.yml`:
```yaml
ports:
  - "your-free-port:4000"  # Change your-free-port to an available port
```

### Development Workflow

1. **Make changes** to your fork
2. **Test locally** using the build environment
3. **Build and push** your custom image
4. **Update** other projects to use your new image tag
5. **Deploy** to production using your custom image

### Security Notes

- Never commit your `GITHUB_TOKEN` to version control
- Use environment variables or secure secret management
- Your custom images are public by default on GHCR
- Consider using private repositories for sensitive customizations

---

For questions or issues with this custom build process, check the original LiteLLM documentation or your fork's repository. 