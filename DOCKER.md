# Docker

Dockerfile and docker-compose.yml provide alternative for installations and development

Some tweaking is expected to suit a production deployment

## Build

```shell
docker-compose build
```

## AdBlock Zone

The example container writes the generated rpz-adblocker.zone file under /bind-adblock

Docker-compose file has an options for using either a volume (i.e containerized bind9 integration) or host mount point (i.e. bind9 running on the docker host os) for that path.

## Deploy

```shell
docker-compose up -d
```

## Running Considerations

### Cron

The current image runs the python script at startup and then exits.
There is no cron scheduler provided at this time.

### On Demand

Once deployed, issuing a run will start the container again, run the update script, then exit after writing the zone file.

```shell
docker run bind-adblock_updater
```

### Bind9 Zone reloads

You might wish to combine bind-adblock and bind9 into the same container in which a cron service controls executing this python script and in turn can trigger named to reload the zone. 

An aggressive workaround is start the adblock updater container then fully restart the bind9 container.

```shell
docker-compose up updater >/dev/null 2>&1 && docker-compose restart bind9 >/dev/null 2>&1
```

