FROM mcr.microsoft.com/dotnet/sdk:11.0-preview-alpine AS builder
RUN apk add --no-cache clang zlib-dev musl-dev
WORKDIR /src

COPY FraudApi/FraudApi.csproj FraudApi/
COPY FraudApi.PreProcessor/FraudApi.PreProcessor.csproj FraudApi.PreProcessor/
RUN dotnet restore FraudApi/FraudApi.csproj -r linux-musl-x64

COPY . .

WORKDIR /src/FraudApi.PreProcessor
RUN dotnet publish -c Release -o /app/preprocessor

RUN /app/preprocessor/FraudApi.PreProcessor /src/resources

WORKDIR /src/FraudApi
RUN dotnet publish FraudApi.csproj -c Release -r linux-musl-x64 -o /app/publish /p:PublishAot=true

FROM alpine:3.21
WORKDIR /appa

COPY --from=builder /app/publish .
COPY --from=builder /src/resources /resources

ENV RESOURCES_PATH=/resources
ENTRYPOINT ["./FraudApi"]