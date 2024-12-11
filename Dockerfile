FROM mcr.microsoft.com/dotnet/sdk:7.0-alpine AS build
WORKDIR /app
COPY . .
RUN git submodule update --init --recursive
RUN dotnet restore
RUN dotnet publish -o /app/published-app
FROM mcr.microsoft.com/dotnet/aspnet:7.0-alpine AS runtime
WORKDIR /app
COPY --from=build /app/published-app /app
ENTRYPOINT ["dotnet", "/app/AuthAPI.dll"]
