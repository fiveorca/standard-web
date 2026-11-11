FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:25-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system im \
    && useradd --system --gid im --home-dir /app im \
    && mkdir -p /app/attachments \
    && chown -R im:im /app
WORKDIR /app
COPY --from=build /build/target/im-service.jar /app/im-service.jar
USER im
EXPOSE 8080 9090
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseContainerSupport"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/im-service.jar"]
