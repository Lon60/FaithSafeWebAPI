# Stage 1: Build the application
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /app

# Copy Gradle wrapper and build files
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

# Copy source code
COPY src src

# Ensure gradlew is executable
RUN chmod +x gradlew

# Build the application
RUN ./gradlew bootJar

# Stage 2: Create the runtime image
FROM eclipse-temurin:17-jdk-alpine

VOLUME /tmp

# Copy the JAR file from the builder stage
ARG JAR_FILE=/app/build/libs/FaithSafeWebApi-0.1.0-ALPHA.jar
COPY --from=builder ${JAR_FILE} app.jar

# Copy the custom properties file
COPY src/main/resources/application-docker.properties application-docker.properties

# Set the entry point and pass environment variables
ENV SERVER_PORT=8080
ENV DATABASE_USERNAME=root
ENV DATABASE_PASSWORD=root
ENTRYPOINT ["sh", "-c", "java -Dspring.profiles.active=docker -Dserver.port=${SERVER_PORT} -Dspring.datasource.url=jdbc:postgresql://$HOST_NAME:5432/faithsafeapi -Dspring.datasource.username=${DATABASE_USERNAME} -Dspring.datasource.password=${DATABASE_PASSWORD} -jar /app.jar"]
