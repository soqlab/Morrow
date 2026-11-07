# Local variant of the e2e backend image: the checkout's backend code on top of an image that
# already has backend/requirements.txt installed, so a laptop does not reinstall every dependency.
#   docker build -t morrow-e2e-backend:local -f deploy/e2e/backend-local.Dockerfile --build-arg BASE=<image> backend
# CI builds backend/Dockerfile instead.
ARG BASE
FROM ${BASE}
WORKDIR /app
COPY . /app
