FROM adoptopenjdk/openjdk14
RUN ln -s $JAVA_HOME/bin/java /usr/bin/java
RUN mkdir /app
WORKDIR /app
COPY . .
RUN ./gradlew assemble
ENTRYPOINT ["/usr/bin/java", "-jar", "build/libs/MF REST API-0.0.1-SNAPSHOT.jar"]
