FROM openjdk:latest
COPY ./build /usr/src/MF-REST-API/build
WORKDIR /usr/src/MF-REST-API
ENTRYPOINT ["/usr/bin/java", "-jar", "build/libs/MF REST API-0.0.1-SNAPSHOT.jar"]
