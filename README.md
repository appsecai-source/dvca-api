# Damn Vulnerable C# Application (API Only)

## Getting Started

**Note:** This is a deliberately vulnerable app, please do not host it on production or Internet/public facing servers. Use with caution.

### Docker

```
docker-compose up
```

### Manual

Install the .NET 8 SDK
[Microsoft .NET SDK](https://dotnet.microsoft.com/download)

Restore dependencies:

```
dotnet restore
```

Start application server:

```
dotnet run
```

Start application server with watcher for auto-reload on change:

```
dotnet watch run
```

The app now applies EF Core migrations on startup, so you do not need to run
`dotnet ef database update` just to start it.

## Build Docker

* To build a docker image run the following command

```bash
docker build -t appsecco/dvcsharp .
```

* To run the docker container

```bash
docker run -d --name dvcsharp -it -p 5000:5000 appsecco/dvcsharp
```

## Solution

The [documentation-dvcsharp-book](./documentation-dvcsharp-book) folder has instructions to use the app and exploit vulnerabilities that have been programmed.
