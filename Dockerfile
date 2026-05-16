FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:11.0-preview-alpine AS builder
RUN apk add --no-cache clang zlib-dev musl-dev
WORKDIR /src

# Restore — cached unless .csproj files change
COPY FraudApi.Shared/FraudApi.Shared.csproj FraudApi.Shared/
COPY FraudApi.PreProcessor/FraudApi.PreProcessor.csproj FraudApi.PreProcessor/
COPY FraudApi/FraudApi.csproj FraudApi/
RUN dotnet restore FraudApi/FraudApi.csproj -r linux-musl-x64

# Preprocessor source — cached unless preprocessor code changes
COPY FraudApi.Shared/ FraudApi.Shared/
COPY FraudApi.PreProcessor/ FraudApi.PreProcessor/
RUN dotnet publish FraudApi.PreProcessor/FraudApi.PreProcessor.csproj -c Release -o /app/preprocessor

# Resources — cached unless resources change (references.json.gz is the heavy input)
COPY resources/ resources/
RUN /app/preprocessor/FraudApi.PreProcessor /src/resources

# API source — only this layer reruns on API code changes
COPY FraudApi/ FraudApi/
WORKDIR /src/FraudApi
RUN dotnet publish FraudApi.csproj -c Release -r linux-musl-x64 -o /app/publish /p:PublishAot=true

FROM --platform=linux/amd64 alpine:3.21
WORKDIR /appa

COPY --from=builder /app/publish .
COPY --from=builder /src/resources /resources

ENV RESOURCES_PATH=/resources
ENTRYPOINT ["./FraudApi"]
