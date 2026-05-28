FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:11.0-preview-alpine AS builder
RUN apk add --no-cache clang zlib-dev musl-dev
WORKDIR /src

# Restore — cached unless .csproj files change
COPY FraudApi.Shared/FraudApi.Shared.csproj FraudApi.Shared/
COPY FraudApi.PreProcessor/FraudApi.PreProcessor.csproj FraudApi.PreProcessor/
COPY FraudApi/FraudApi.csproj FraudApi/
RUN dotnet restore FraudApi/FraudApi.csproj -r linux-musl-x64

# Preprocessor + API source — cached unless source changes
COPY FraudApi.Shared/ FraudApi.Shared/
COPY FraudApi.PreProcessor/ FraudApi.PreProcessor/
RUN dotnet publish FraudApi.PreProcessor/FraudApi.PreProcessor.csproj -c Release -o /app/preprocessor

# API AOT build — cached independently of resources/bucket size
COPY FraudApi/ FraudApi/
WORKDIR /src/FraudApi
RUN dotnet publish FraudApi.csproj -c Release -r linux-musl-x64 -o /app/publish /p:PublishAot=true

# Resources — only invalidated when resources or BUCKET_SIZE change
WORKDIR /src
ARG BUCKET_SIZE=2048
ARG VP_SAMPLE_SIZE=20
ARG MAX_LEAF_SEG=512
COPY resources/ resources/
RUN BUCKET_SIZE=$BUCKET_SIZE VP_SAMPLE_SIZE=$VP_SAMPLE_SIZE MAX_LEAF_SEG=$MAX_LEAF_SEG /app/preprocessor/FraudApi.PreProcessor /src/resources

FROM --platform=linux/amd64 alpine:3.21
WORKDIR /appa

COPY --from=builder /app/publish .
COPY --from=builder /src/resources /resources

ENV RESOURCES_PATH=/resources
ENTRYPOINT ["./FraudApi"]
