# MulVAL Attack Graph Docker (Windows)

Windows-friendly starter project for running MulVAL attack graph generation with Docker.

## Defaults (already set for your environment)

- `MULVAL_MOUNT_DIR=F:\mulval-docker`
- `DEFAULT_INPUT` and `DEFAULT_RULES` are in `mulval-docker.bat`

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

This runs with the current values of `DEFAULT_INPUT` and `DEFAULT_RULES` in `mulval-docker.bat`, and updates attack graph files in `F:\mulval-docker`.

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

Now `.env` only controls container/image/mount path.
`INPUT_FILE` and `RULES_FILE` in `.env` are ignored by design.
So changing `set "DEFAULT_INPUT=..."` or `set "DEFAULT_RULES=..."` in `mulval-docker.bat` takes effect directly.

## Mount Path Changes

If container mount path changed earlier, run `mulval-docker.bat up` (or `run`), and the script will recreate the container with the current mount config.
