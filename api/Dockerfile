FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
ARG JAR_FILE=build/libs/FaithSafeWebApi-0.1.0-ALPHA.jar
COPY ${JAR_FILE} app.jar
COPY src/main/resources/application-docker.properties application-docker.properties
ENTRYPOINT ["java","-Dspring.profiles.active=docker","-jar","/app.jar"]