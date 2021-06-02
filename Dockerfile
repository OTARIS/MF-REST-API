FROM openjdk:latest
COPY ./build /usr/src/MF-REST-API/build
WORKDIR /usr/src/MF-REST-API
ENV MF_PROPERTIES=/mf/config.yml
ENTRYPOINT ["/usr/bin/java", "-jar", "build/libs/MF REST API-0.0.1-SNAPSHOT.jar"]
