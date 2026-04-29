FROM mcr.microsoft.com/dotnet/sdk:8.0
LABEL MAINTAINER "Appsecco"

ENV ASPNETCORE_URLS=http://0.0.0.0:5000

COPY . /app

WORKDIR /app

RUN dotnet restore ./dvcsharp-core-api.csproj

RUN groupadd -r appuser && useradd -r -g appuser appuser && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

CMD ["bash", "./start.sh"]
