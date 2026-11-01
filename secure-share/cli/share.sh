#!/usr/bin/env sh
# Runs the secure-share CLI. One-time setup (from the project root):
#   mvn -q package -DskipTests dependency:copy-dependencies -DoutputDirectory=target/cli-lib -DincludeScope=runtime
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec java --enable-native-access=ALL-UNNAMED -cp "$ROOT/target/classes:$ROOT/target/cli-lib/*" com.secureshare.cli.ShareCli "$@"
