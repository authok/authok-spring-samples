# FROM openjdk:8-jre-alpine
FROM openjdk:11.0.8-jre
COPY target/authok-spring-samples-1.0-SNAPSHOT.jar ./service/authok-spring-samples-1.0-SNAPSHOT.jar
CMD java -jar ./service/authok-spring-samples-1.0-SNAPSHOT.jar