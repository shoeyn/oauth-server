# Stage 1: Build Spring Boot JAR from source
FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /build

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


