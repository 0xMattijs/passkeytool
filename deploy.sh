#!/usr/bin/env bash
# Deploy passkeytool serve to Cloud Run as a public test server.
#
# Usage: PROJECT=my-project [REGION=europe-west4] [ORIGIN=https://passkeys.example.com]
#        [GCLOUD_ACCOUNT=me@example.com] ./deploy.sh
#
# ORIGIN is a custom domain mapped to the service. Without it, the server
# uses the service's run.app URL. With it, the run.app URL stays usable as a
# related origin.
#
# Builds the image locally with Docker, pushes it to Artifact Registry, and
# deploys it with public limits. See "Host it publicly" in the README.
set -euo pipefail

: "${PROJECT:?set PROJECT to your Google Cloud project ID}"
REGION=${REGION:-europe-west4}
REPO=${REPO:-cloud-run-source-deploy}
SERVICE=${SERVICE:-passkeytool}
gc=(gcloud --project="$PROJECT")
[[ -n ${GCLOUD_ACCOUNT:-} ]] && gc+=(--account="$GCLOUD_ACCOUNT")

cd "$(dirname "$0")"
version=$(git describe --tags --always --dirty)
registry=$REGION-docker.pkg.dev
image=$registry/$PROJECT/$REPO/$SERVICE:$version

if ! "${gc[@]}" artifacts repositories describe "$REPO" --location="$REGION" >/dev/null 2>&1; then
  "${gc[@]}" artifacts repositories create "$REPO" --location="$REGION" --repository-format=docker
fi

docker build --build-arg VERSION="$version" -t "$image" .
"${gc[@]}" auth print-access-token | docker login -u oauth2accesstoken --password-stdin "https://$registry"
trap 'docker logout "https://$registry" >/dev/null' EXIT
docker push "$image"

# Cloud Run's deterministic URL: https://SERVICE-PROJECT_NUMBER.REGION.run.app
number=$("${gc[@]}" projects describe "$PROJECT" --format='value(projectNumber)')
runapp=https://$SERVICE-$number.$REGION.run.app
url=${ORIGIN:-$runapp}
origins=$url
[[ $url != "$runapp" ]] && origins=$url,$runapp
notice="Public test server. Accounts are deleted whenever the server restarts, which happens after a few idle minutes. Don't use your real name, and remove test passkeys from your device when you're done."

args=(serve -origin "$origins" -aaguids /tmp/aaguid.json
  -max-users 1000 -max-passkeys 10 -rate-limit 30 -trust-proxy -notice "$notice")
joined=$(IFS='|'; echo "${args[*]}")

"${gc[@]}" run deploy "$SERVICE" --image="$image" --region="$REGION" \
  --allow-unauthenticated --max-instances=1 --memory=256Mi --cpu=1 \
  --concurrency=80 --timeout=60 --quiet --args="^|^$joined"

echo "Deployed $version to $url"
