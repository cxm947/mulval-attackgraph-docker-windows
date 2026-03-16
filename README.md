# MulVAL Attack Graph Docker (Windows)

Windows-friendly starter project for running MulVAL attack graph generation with Docker.

## Defaults (already set for your environment)

- `MULVAL_MOUNT_DIR=F:\mulval-docker`
- `INPUT_FILE=S2.P`
- `RULES_FILE=rules5.P`

## Files

- `mulval-docker.bat`: main driver script
- `.env.example`: environment list config template
- `docker-compose.yml`: compose startup option
- `S2.P`: sample/user input model
- `rules5.P`: rules file

## Quick Start

1. Copy config:

```bat
copy .env.example .env
```

2. Run directly (double click also works):

```bat
mulval-docker.bat
```

This runs `graph_gen.sh -v -r rules5.P S2.P` and updates attack graph files in `F:\mulval-docker`.

## Common Commands

```bat
mulval-docker.bat status
mulval-docker.bat up
mulval-docker.bat recreate
mulval-docker.bat run
mulval-docker.bat run S2.P rules5.P
mulval-docker.bat shell
mulval-docker.bat down
```

`up` and `run` both recreate the container with current `MULVAL_MOUNT_DIR` to avoid stale mounts.

## Compose Mode

```bat
docker compose up -d
docker exec mulval-attackgraph bash -lc "cd /input && graph_gen.sh -v -r rules5.P S2.P"
docker compose down
```

## Why DEFAULT_* may look ineffective

`mulval-docker.bat` loads `.env` first. If `.env` has `INPUT_FILE` or `RULES_FILE`, those values override script defaults.

If you change defaults in the BAT file, also update `.env` (or remove those keys in `.env`).

## Mount Path Changes

If container mount path changed earlier, run `mulval-docker.bat up` (or `run`), and the script will recreate the container with the current mount config.
