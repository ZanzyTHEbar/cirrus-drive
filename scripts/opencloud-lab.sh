#!/usr/bin/env bash
# Disposable OpenCloud discovery lab. This script never contacts a user's server.
set -euo pipefail

image='opencloudeu/opencloud-rolling@sha256:bd57f039d0dd3df510fb25f178beefdf0b1f049097285feead607824460e6506'
container=''

cleanup() {
    if [[ -n "$container" ]]; then
        if ! docker rm -f "$container" >/dev/null; then
            echo "failed to remove owned lab container $container" >&2
            return 1
        fi
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "pinned OpenCloud lab image is not installed; see README for the explicit pull command" >&2
    exit 1
fi

container=$(docker create --pull never --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --no-healthcheck --log-driver none --pids-limit 256 \
    --memory 768m --cpus 1 \
    --tmpfs /etc/opencloud:rw,nosuid,nodev,noexec,size=32m,uid=1000,gid=1000,mode=0700 \
    --tmpfs /var/lib/opencloud:rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=0700 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700 \
    --env OC_URL=https://localhost:9200 \
    --env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= --env NO_PROXY='*' \
    --env http_proxy= --env https_proxy= --env all_proxy= --env no_proxy='*' \
    --entrypoint /bin/sh "$image" \
    -c 'opencloud init --quiet --insecure true >/dev/null 2>&1 && exec opencloud server >/dev/null 2>&1')
docker start "$container" >/dev/null

# Both requests and the disposable TLS exception stay inside the isolated container.
response=''
for _ in {1..40}; do
    if response=$(docker exec "$container" curl --silent --fail --insecure --noproxy '*' \
        --max-time 2 --max-filesize 65536 --get \
        --data-urlencode 'resource=https://localhost:9200' \
        --data-urlencode 'rel=http://openid.net/specs/connect/1.0/issuer' \
        --data-urlencode 'platform=desktop' \
        'https://localhost:9200/.well-known/webfinger' 2>/dev/null); then
        break
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
        echo 'isolated OpenCloud exited before discovery was ready' >&2
        exit 1
    fi
    sleep 1
done

if [[ -z "$response" ]]; then
    echo 'isolated OpenCloud desktop WebFinger did not become ready' >&2
    exit 1
fi

metadata=''
for _ in {1..20}; do
    if metadata=$(docker exec "$container" curl --silent --fail --insecure --noproxy '*' \
        --max-time 2 --max-filesize 65536 \
        'https://localhost:9200/.well-known/openid-configuration' 2>/dev/null); then
        break
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
        echo 'isolated OpenCloud exited before OpenID metadata was ready' >&2
        exit 1
    fi
    sleep 1
done
if [[ -z "$metadata" ]]; then
    echo 'isolated OpenID metadata did not become ready' >&2
    exit 1
fi

printf '%s\n%s\n' "$response" "$metadata" | python3 -c '
import json, sys
from urllib.parse import urlsplit

raw = sys.stdin.read()
decoder = json.JSONDecoder()
data, end = decoder.raw_decode(raw)
metadata = json.loads(raw[end:])
relation = "http://openid.net/specs/connect/1.0/issuer"
links = data.get("links", [])
issuers = [link.get("href") for link in links if isinstance(link, dict) and link.get("rel") == relation]
props = data.get("properties", {})
client_id = props.get("http://opencloud.eu/ns/oidc/client_id")
scopes = props.get("http://opencloud.eu/ns/oidc/scopes")
if (data.get("subject") != "https://localhost:9200" or len(issuers) != 1
        or not isinstance(issuers[0], str) or urlsplit(issuers[0]).scheme != "https"
        or not urlsplit(issuers[0]).netloc or not isinstance(client_id, str) or not client_id
        or not isinstance(scopes, list) or "openid" not in scopes
        or not all(isinstance(scope, str) and scope for scope in scopes)):
    raise SystemExit("isolated desktop WebFinger response lacks required discovery fields")
if metadata.get("issuer") != issuers[0]:
    raise SystemExit("isolated OpenID issuer does not match WebFinger")
for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
    value = metadata.get(key)
    if not isinstance(value, str):
        raise SystemExit("isolated OpenID metadata lacks a required endpoint")
    endpoint = urlsplit(value)
    if endpoint.scheme != "https" or not endpoint.netloc or endpoint.username or endpoint.password or endpoint.fragment:
        raise SystemExit("isolated OpenID metadata has an invalid endpoint")
print("isolated OpenCloud 9.0.0 desktop WebFinger and OpenID issuer metadata validated")
'
