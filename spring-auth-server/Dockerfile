# Stage 1: Build Spring Boot JAR from source
FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /build

# Corporate TLS interception: on networks that MITM HTTPS (a proxy re-signing Maven Central
# with an internal CA), Maven fails with "PKIX path building failed". A CA bundle is supplied at
# build time via a Docker build secret (id=ca_bundle) — it is mounted transiently for this RUN
# only and is NEVER copied into an image layer or committed to the repo. If the secret is absent
# or empty (e.g. building off the corporate network), the step is skipped gracefully.
#
# docker-compose.yml wires this secret up automatically from a local, git-ignored CA bundle.
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then \
      cp /run/secrets/ca_bundle /usr/local/share/ca-certificates/extra-ca-bundle.crt && \
      update-ca-certificates && \
      csplit -z -f /tmp/extra-cert- -b '%02d.pem' /run/secrets/ca_bundle '/-----BEGIN CERTIFICATE-----/' '{*}' && \
      for cert in /tmp/extra-cert-*.pem; do \
        keytool -importcert -noprompt -trustcacerts \
          -alias "extra-$(basename "$cert" .pem)" \
          -file "$cert" -cacerts -storepass changeit || true; \
      done && \
      rm -f /tmp/extra-cert-*.pem; \
    else \
      echo "No ca_bundle build secret provided; skipping custom CA import."; \
    fi

# Copy dependency definition and download dependencies for caching
COPY pom.xml .
RUN mvn dependency:go-offline -B || true

# Copy source code and build artifact
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Lean runtime container
FROM eclipse-temurin:25-jre-noble
WORKDIR /app
COPY --from=builder /build/target/spring-auth-server-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 9000
ENTRYPOINT ["java", "-jar", "app.jar"]


