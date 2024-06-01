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

# Set the entry point
ENTRYPOINT ["java", "-Dspring.profiles.active=docker", "-jar", "/app.jar"]
