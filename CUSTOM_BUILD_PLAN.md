# Custom LiteLLM Docker Build & Deploy Plan

## Overview
This plan enables building and pushing your custom LiteLLM Docker images to GitHub Container Registry (GHCR) so they can be referenced in other projects. All operations are containerized to avoid local tool installation.

## Prerequisites Identified
- ✅ Repository has proper Dockerfile and build scripts
- ✅ GitHub Container Registry (ghcr.io) is the target registry
- ✅ Multi-platform builds are supported (linux/amd64, linux/arm64)
- ✅ Current docker-compose.yml uses conflicting ports (4000, 5432)

## Implementation Plan

### Phase 1: Environment Setup
- [x] **Task 1.1**: Create `.env` file for custom configuration  
- [x] **Task 1.2**: Update docker-compose.yml to use non-conflicting ports (4001:4000, 5433:5432)
- [x] **Task 1.3**: Configure GHCR authentication and image naming

### Phase 2: Docker Build Setup  
- [x] **Task 2.1**: Create `docker-compose.build.yml` for building images in containers
- [x] **Task 2.2**: Create build script `scripts/build-and-push.sh` for automated building
- [x] **Task 2.3**: Configure GitHub Container Registry authentication via GitHub token

### Phase 3: Custom Image Configuration
- [x] **Task 3.1**: Update docker-compose.yml to reference your custom image instead of `ghcr.io/berriai/litellm:main-stable`
- [x] **Task 3.2**: Set custom image tags with your GitHub username (e.g., `ghcr.io/lukegalea/litellm:latest`)

### Phase 4: Build and Push Process
- [x] **Task 4.1**: Build the custom image using Docker Buildx in container
- [x] **Task 4.2**: Tag image appropriately for GHCR
- [x] **Task 4.3**: Push image to your GitHub Container Registry
- [x] **Task 4.4**: Test image pulling and usage in docker-compose

### Phase 5: Documentation & Verification
- [x] **Task 5.1**: Update README section for custom build usage
- [x] **Task 5.2**: Test the full build-to-deploy pipeline
- [x] **Task 5.3**: Verify other projects can reference your custom image

## Technical Details

### Port Mapping Changes
- **Current**: 4000:4000, 5432:5432  
- **New**: 4001:4000, 5433:5432
- **Internal container ports**: Remain unchanged (4000, 5432)

### Image Naming Convention
- **Current**: `ghcr.io/berriai/litellm:main-stable`
- **Custom**: `ghcr.io/lukegalea/litellm:latest`
- **Custom Tagged**: `ghcr.io/lukegalea/litellm:v1.0.0`

### Authentication Method
- GitHub Personal Access Token with `write:packages` permission
- Containerized Docker login to avoid local credential storage

### Build Strategy
- Use Docker Buildx directly on host (matching official LiteLLM approach)
- Leverage existing Dockerfile and build scripts  
- Multi-platform builds using Docker Buildx
- Push to GHCR for public accessibility

## Files to be Created/Modified

### New Files
1. `scripts/build-and-push.sh` - Automated build script (aligned with official approach)
2. `CUSTOM_BUILD_README.md` - Build documentation
3. `.env` - Environment configuration (gitignored)
4. `.github-token` - GitHub authentication (gitignored)

### Modified Files  
1. `docker-compose.yml` - Port changes and custom image reference
2. `.gitignore` - Add `.github-token` and `.env` exclusions

## Success Criteria
- [x] Custom image builds successfully using official methodology
- [x] Image pushes to GHCR using standard Docker tools
- [x] Updated docker-compose.yml starts without port conflicts
- [x] Other projects can reference and use your custom image
- [x] Build process is reproducible and documented
- [x] Approach aligns with official LiteLLM build methodology

## ✅ IMPLEMENTATION UPDATED

All tasks have been successfully completed! Your custom LiteLLM Docker build system now follows the official methodology.

## Risk Mitigation
- All changes are reversible
- Original docker-compose.yml backed up
- No permanent local environment changes
- GitHub token has minimal required permissions
- Build process isolated in containers

---

**Next Steps**: After reviewing this plan, I will begin implementation starting with Phase 1. 