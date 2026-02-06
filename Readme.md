# Spring Booth Auth

<p align="center">
  <img src="https://brandlogos.net/wp-content/uploads/2026/01/spring_boot_symbol-logo_brandlogos.net_tkqz9-300x300.png" />
</p>

This is my first time working on API server using java and by the time i started learning spring boot... boy oh boy... it's pretty complicated compared to previous API framework like  nodejs, django or gofiber. The spring boot project structure has a similiarty to nestjs project structure like entity, service, repository and whatnot which is nice.

## How to run spring boot

```bash
./mvnw spring-boot:run
```

If somehow there is an error after installing new package

```bash
./mvnw clean package
```

## Installing Java using SDKMAN

Make sure basic tools are installed (curl for the installer, and zip/unzip for extracting SDKs):

SDKMAN requires a basic UNIX toolchain (bash, curl, zip/unzip).

```bash
sudo apt update
sudo apt install -y curl zip unzip tar gzip ca-certificates
```

Run the official installer (official recommended method):

```bash
curl -s "https://get.sdkman.io" | bash
```

```bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
```

Find available Java candidates and identifiers (you’ll see vendor tags like `tem`, `zulu`, `liberica`, etc.):

```bash
sdk list java
```

Install a chosen entry exactly as shown, for example (replace `25.0.1-tem` with the identifier you pick):

```bash
sdk install java 25.0.1-tem
```

You can also install the latest stable Java with:

```bash
sdk install java
```

To set a JDK as the default for all new shells:

```bash
sdk default java 25.0.1-tem
```

To switch only for the current shell session (non-permanent):

```bash
sdk use java 17.0.8-tem
```

Check what’s active:

```bash
sdk current java
java -version
```

## First time configuration

From a terminal in the folder where you want the project:
This creates a Maven project with the usual structure (and a Maven wrapper mvnw). You can also use the web UI at [start.spring.io](https://start.spring.io)

```bash
curl "https://start.spring.io/starter.tgz" \
  -d bootVersion=4.0.1 \
  -d type=maven-project \
  -d language=java \
  -d packaging=jar \
  -d javaVersion=25 \
  -d groupId=com.myspring \
  -d artifactId=spring-auth \
  -d name="Spring Auth" \
  -d description="Simple Spring Auth service" \
  -d packageName=com.myspring.spring-auth \
  -d baseDir=spring-auth \
  -d dependencies=web,actuator \
  | tar -xzvf -
cd spring-auth
```
