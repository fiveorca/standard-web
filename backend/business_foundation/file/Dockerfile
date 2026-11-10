# 构建阶段
FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

# 运行阶段
FROM eclipse-temurin:25-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --create-home app
WORKDIR /app
COPY --from=builder /build/target/file-service.jar /app/file-service.jar
RUN mkdir -p /app/data/storage /app/data/upload-tmp && chown -R app:app /app/data
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"
EXPOSE 8082
USER 10001
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/file-service.jar"]
