FROM eclipse-temurin:25-jre-noble
WORKDIR /app
COPY target/spring-auth-server-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 9000
ENTRYPOINT ["java", "-jar", "app.jar"]

