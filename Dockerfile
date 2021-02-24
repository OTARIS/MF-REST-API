FROM openjdk:latest
COPY ./build /usr/src/NutriSafe/build
WORKDIR /usr/src/NutriSafe
ENTRYPOINT [“java”, “-jar”, “build/libs/NutriSafe REST API-0.0.1-SNAPSHOT.jar”]
