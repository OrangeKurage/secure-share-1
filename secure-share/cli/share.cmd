@echo off
rem Runs the secure-share CLI. One-time setup (from the project root):
rem   mvn -q package -DskipTests dependency:copy-dependencies "-DoutputDirectory=target/cli-lib" "-DincludeScope=runtime"
set "ROOT=%~dp0.."
java --enable-native-access=ALL-UNNAMED -cp "%ROOT%\target\classes;%ROOT%\target\cli-lib\*" com.secureshare.cli.ShareCli %*
