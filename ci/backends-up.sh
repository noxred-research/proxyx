#!/usr/bin/env bash
# Start the throwaway backend services the integration tests of docs/backends.md need, each with
# its data in tmpfs, and print the PROXYX_TEST_* variables that point at them (one NAME=value per
# line; the workflow appends them to $GITHUB_ENV). Remove everything with ci/backends-down.sh.
#
#   BACKENDS_SUFFIX  container name suffix (default: $GITHUB_RUN_ID, else the shell's PID)
#   BACKENDS_PORTS   first of the ports used (default 19000); the services use the next 12
set -euo pipefail

SUFFIX="${BACKENDS_SUFFIX:-${GITHUB_RUN_ID:-$$}}"
BASE="${BACKENDS_PORTS:-19000}"
S3=$((BASE)) CH=$((BASE + 1)) OS=$((BASE + 2)) ES=$((BASE + 3)) KAFKA=$((BASE + 4)) KCTL=$((BASE + 5))
AMQP=$((BASE + 6)) MGMT=$((BASE + 7)) REDIS=$((BASE + 8)) CHTCP=$((BASE + 9)) CHMYSQL=$((BASE + 10)) CHINTER=$((BASE + 11)) MINIO=$((BASE + 12))
MQ_USER=guest MQ_PASS=guest # the broker image's built-in test account, reachable from 127.0.0.1 only
S3_ACCESS=proxyxci
S3_SECRET="proxyxci-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

run() { docker run -d --name "proxyx-ci-$1-$SUFFIX" "${@:2}" >/dev/null; }
wait_for() { # name, command...
  local name="$1"; shift
  for _ in $(seq 90); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  docker logs "proxyx-ci-$name-$SUFFIX" >&2 || true
  echo "service $name did not become ready" >&2
  exit 1
}

# an S3-API object store (the `self-hosted` profile)
run s3 --user 0 -p "127.0.0.1:$S3:9000" --tmpfs /data:rw,size=1g --tmpfs /logs:rw,size=256m \
  -e RUSTFS_ACCESS_KEY="$S3_ACCESS" -e RUSTFS_SECRET_KEY="$S3_SECRET" -e RUSTFS_ADDRESS=0.0.0.0:9000 \
  rustfs/rustfs@sha256:b81d16a90ee25bd9511280127ca1471788c6e874cf0f0da759645f46b2dc1d74 /data
# the other verified S3-API server for the `self-hosted` profile (the S3 suite runs against both)
run minio --user 0 -p "127.0.0.1:$MINIO:9000" --tmpfs /data:rw,size=1g \
  -e MINIO_ROOT_USER="$S3_ACCESS" -e MINIO_ROOT_PASSWORD="$S3_SECRET" \
  docker.io/bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c \
  minio server /data --address :9000
# ClickHouse on the host network, so that it reaches the object store on 127.0.0.1
run clickhouse --network host --tmpfs /var/lib/clickhouse:rw,size=2g \
  clickhouse/clickhouse-server@sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77 \
  -- --http_port="$CH" --tcp_port="$CHTCP" --mysql_port="$CHMYSQL" --interserver_http_port="$CHINTER" --listen_host=127.0.0.1
# OpenSearch 2.19.7: the capture store suite expects its regexp behaviour (2.19.1 differs)
run opensearch -p "127.0.0.1:$OS:9200" --tmpfs /usr/share/opensearch/data:rw,size=1g,mode=1777 \
  -e discovery.type=single-node -e cluster.routing.allocation.disk.threshold_enabled=false -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  opensearchproject/opensearch@sha256:3bfa1ec74d56928c2e018033d45c460ce2c0ea65a5cedd577de3102326c31b89
# Elasticsearch 8.17.0: the version the capture store suite is documented against
run elasticsearch -p "127.0.0.1:$ES:9200" --tmpfs /usr/share/elasticsearch/data:rw,size=1g,mode=1777 \
  -e discovery.type=single-node -e xpack.security.enabled=false -e cluster.routing.allocation.disk.threshold_enabled=false -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  docker.elastic.co/elasticsearch/elasticsearch@sha256:2f602552550869fb29b6fd5848c5118d3ef3a2e1d5d45802e3ab9088cb2de8e2
run kafka --network host --tmpfs /var/lib/kafka/data:rw,size=1g,mode=1777 \
  -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENERS="PLAINTEXT://127.0.0.1:$KAFKA,CONTROLLER://127.0.0.1:$KCTL" \
  -e KAFKA_ADVERTISED_LISTENERS="PLAINTEXT://127.0.0.1:$KAFKA" -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS="1@127.0.0.1:$KCTL" -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  apache/kafka@sha256:fbc7d7c428e3755cf36518d4976596002477e4c052d1f80b5b9eafd06d0fff2f
run rabbitmq -p "127.0.0.1:$AMQP:5672" -p "127.0.0.1:$MGMT:15672" --tmpfs /var/lib/rabbitmq:rw,size=1g,mode=1777 \
  rabbitmq@sha256:753099a19b577c322117f793f864b3129cbba96d40317221a69d73976e3c843c
# Redis (the RESP twin of the Valkey that the unit job runs)
run redis -p "127.0.0.1:$REDIS:6379" \
  redis@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3 redis-server --save '' --appendonly no

wait_for s3 curl -s -o /dev/null "http://127.0.0.1:$S3/"
wait_for minio curl -sf "http://127.0.0.1:$MINIO/minio/health/live"
wait_for clickhouse curl -sf "http://127.0.0.1:$CH/ping"
# a new server creates system.query_log at its first flush; the capture store tests read it
wait_for clickhouse curl -sf "http://127.0.0.1:$CH/" --data-binary "SYSTEM FLUSH LOGS"
wait_for opensearch curl -sf "http://127.0.0.1:$OS/"
wait_for elasticsearch curl -sf "http://127.0.0.1:$ES/"
wait_for rabbitmq curl -sf -u "$MQ_USER:$MQ_PASS" "http://127.0.0.1:$MGMT/api/overview"
wait_for redis docker exec "proxyx-ci-redis-$SUFFIX" redis-cli ping
wait_for kafka docker exec "proxyx-ci-kafka-$SUFFIX" /opt/kafka/bin/kafka-topics.sh --bootstrap-server "127.0.0.1:$KAFKA" --list

cat <<VARS
PROXYX_TEST_S3_ENDPOINT=http://127.0.0.1:$S3
PROXYX_TEST_S3_MINIO_ENDPOINT=http://127.0.0.1:$MINIO
PROXYX_TEST_S3_ACCESS_KEY=$S3_ACCESS
PROXYX_TEST_S3_SECRET_KEY=$S3_SECRET
PROXYX_TEST_CLICKHOUSE_URL=http://127.0.0.1:$CH
PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE=1
PROXYX_TEST_OPENSEARCH_URL=http://127.0.0.1:$OS
PROXYX_TEST_ELASTICSEARCH_URL=http://127.0.0.1:$ES
PROXYX_TEST_KAFKA_BROKERS=127.0.0.1:$KAFKA
PROXYX_TEST_RABBITMQ_URL=amqp://$MQ_USER:$MQ_PASS@127.0.0.1:$AMQP/%2f
PROXYX_TEST_RABBITMQ_MGMT=http://$MQ_USER:$MQ_PASS@127.0.0.1:$MGMT
PROXYX_TEST_REDIS_URL=redis://127.0.0.1:$REDIS
VARS
