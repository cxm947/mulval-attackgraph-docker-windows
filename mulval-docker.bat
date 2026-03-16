@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "ENV_FILE=%SCRIPT_DIR%\.env"
set "LEGACY_CONFIG_FILE=%SCRIPT_DIR%\mulval.config"

set "DEFAULT_CONTAINER=mulval-attackgraph"
set "DEFAULT_IMAGE=wilbercui/mulval"
set "DEFAULT_MOUNT_DIR=%SCRIPT_DIR%"
set "DEFAULT_INPUT=sample-attack.P"
set "DEFAULT_RULES="

set "CONTAINER=%DEFAULT_CONTAINER%"
set "IMAGE=%DEFAULT_IMAGE%"
set "MOUNT_DIR=%DEFAULT_MOUNT_DIR%"
set "INPUT_FILE=%DEFAULT_INPUT%"
set "RULES_FILE=%DEFAULT_RULES%"

call :load_kv_file "%ENV_FILE%"
call :load_kv_file "%LEGACY_CONFIG_FILE%"
call :normalize_mount_dir
call :resolve_docker || exit /b 1

if "%~1"=="" (
  set "ACTION=run"
) else (
  set "ACTION=%~1"
)

if /I "%ACTION%"=="help" goto :usage
if /I "%ACTION%"=="status" (
  call :check_docker_engine || exit /b 1
  call :print_status
  exit /b 0
)

if /I "%ACTION%"=="up" (
  call :ensure_container || exit /b 1
  call :print_status
  exit /b 0
)

if /I "%ACTION%"=="recreate" (
  call :recreate_container || exit /b 1
  call :print_status
  exit /b 0
)

if /I "%ACTION%"=="down" (
  call :check_docker_engine || exit /b 1
  call :stop_container
  exit /b 0
)

if /I "%ACTION%"=="shell" (
  call :ensure_container || exit /b 1
  echo Opening shell in %CONTAINER% ...
  "%DOCKER%" exec -it "%CONTAINER%" bash
  exit /b !ERRORLEVEL!
)

if /I "%ACTION%"=="run" (
  set "RUN_INPUT=%~2"
  set "RUN_RULES=%~3"
  if not defined RUN_INPUT set "RUN_INPUT=%INPUT_FILE%"
  if not defined RUN_RULES set "RUN_RULES=%RULES_FILE%"
  call :run_mulval "!RUN_INPUT!" "!RUN_RULES!"
  exit /b !ERRORLEVEL!
)

if /I "%ACTION%"=="init-env" (
  call :init_env
  exit /b 0
)

if /I "%ACTION%"=="init-config" (
  call :init_legacy_config
  exit /b 0
)

echo Unknown action: %ACTION%
goto :usage

:usage
echo.
echo MulVAL Attack Graph Docker Driver
echo.
echo Usage:
echo   %~n0.bat status
echo   %~n0.bat up
echo   %~n0.bat recreate
echo   %~n0.bat down
echo   %~n0.bat shell
echo   %~n0.bat run [input.P] [rules.P]
echo   %~n0.bat init-env
echo   %~n0.bat init-config
echo.
echo Double click:
echo   no args = run
echo.
echo Current defaults:
echo   container : %CONTAINER%
echo   image     : %IMAGE%
echo   mount dir : %MOUNT_DIR%
echo   input     : %INPUT_FILE%
if defined RULES_FILE (
  echo   rules     : %RULES_FILE%
) else (
  echo   rules     : ^(built-in default rules^)
)
echo.
echo Config files:
echo   %ENV_FILE%        ^(recommended^)
echo   %LEGACY_CONFIG_FILE% ^(optional legacy^)
echo.
exit /b 1

:resolve_docker
set "DOCKER="
where docker >nul 2>nul && set "DOCKER=docker"
if not defined DOCKER if exist "C:\Program Files\Docker\Docker\resources\bin\docker.exe" set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
if not defined DOCKER (
  echo [ERROR] Docker CLI not found. Please install Docker Desktop first.
  exit /b 1
)
exit /b 0

:check_docker_engine
"%DOCKER%" info >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Docker engine is not running. Start Docker Desktop first.
  exit /b 1
)
exit /b 0

:ensure_container
call :check_docker_engine || exit /b 1

"%DOCKER%" inspect "%CONTAINER%" >nul 2>nul
if errorlevel 1 (
  echo Creating container %CONTAINER% ...
  "%DOCKER%" run -d --name "%CONTAINER%" -v "%MOUNT_DIR%:/input" "%IMAGE%" bash -lc "/root/startSql.bash; tail -f /dev/null" >nul
  if errorlevel 1 (
    echo [ERROR] Failed to create container.
    exit /b 1
  )
)

"%DOCKER%" inspect -f "{{.State.Running}}" "%CONTAINER%" 2>nul | findstr /I /C:"true" >nul
if errorlevel 1 (
  echo Starting container %CONTAINER% ...
  "%DOCKER%" start "%CONTAINER%" >nul
  if errorlevel 1 (
    echo [ERROR] Failed to start container.
    exit /b 1
  )
)
exit /b 0

:recreate_container
call :check_docker_engine || exit /b 1
"%DOCKER%" rm -f "%CONTAINER%" >nul 2>nul
echo Recreating container %CONTAINER% with mount %MOUNT_DIR% ...
"%DOCKER%" run -d --name "%CONTAINER%" -v "%MOUNT_DIR%:/input" "%IMAGE%" bash -lc "/root/startSql.bash; tail -f /dev/null" >nul
if errorlevel 1 (
  echo [ERROR] Failed to recreate container.
  exit /b 1
)
exit /b 0

:stop_container
"%DOCKER%" inspect -f "{{.State.Running}}" "%CONTAINER%" 2>nul | findstr /I /C:"true" >nul
if not errorlevel 1 (
  "%DOCKER%" stop "%CONTAINER%" >nul
  if errorlevel 1 (
    echo [ERROR] Failed to stop container %CONTAINER%.
    exit /b 1
  )
  echo Container stopped: %CONTAINER%
) else (
  echo Container is not running: %CONTAINER%
)
exit /b 0

:print_status
echo.
echo Docker:
"%DOCKER%" version --format "  Client={{.Client.Version}}  Server={{.Server.Version}}" 2>nul
if errorlevel 1 echo   Unable to read docker version.

echo.
echo MulVAL container:
"%DOCKER%" inspect -f "  Name={{.Name}}  Image={{.Config.Image}}  Running={{.State.Running}}  Status={{.State.Status}}  Mount={{range .Mounts}}{{.Source}}:{{.Destination}}{{end}}" "%CONTAINER%" 2>nul
if errorlevel 1 echo   Container not found: %CONTAINER%
echo.
exit /b 0

:run_mulval
set "RUN_INPUT_FILE=%~1"
set "RUN_RULES_FILE=%~2"

if not defined RUN_INPUT_FILE (
  echo [ERROR] Input file is empty.
  exit /b 1
)

if not exist "%MOUNT_DIR%\%RUN_INPUT_FILE%" (
  echo [ERROR] Input file not found: %MOUNT_DIR%\%RUN_INPUT_FILE%
  exit /b 1
)

if defined RUN_RULES_FILE (
  if not exist "%MOUNT_DIR%\%RUN_RULES_FILE%" (
    echo [ERROR] Rules file not found: %MOUNT_DIR%\%RUN_RULES_FILE%
    exit /b 1
  )
)

call :ensure_container || exit /b 1

set "INNER_CMD=cd /input && graph_gen.sh -v"
if defined RUN_RULES_FILE set "INNER_CMD=!INNER_CMD! -r \"%RUN_RULES_FILE%\""
set "INNER_CMD=!INNER_CMD! \"%RUN_INPUT_FILE%\""

echo Running MulVAL...
echo   input: %RUN_INPUT_FILE%
if defined RUN_RULES_FILE (
  echo   rules: %RUN_RULES_FILE%
) else (
  echo   rules: built-in default
)

"%DOCKER%" exec "%CONTAINER%" bash -lc "!INNER_CMD!"
if errorlevel 1 (
  echo [ERROR] MulVAL run failed.
  exit /b 1
)

echo.
echo Done. Generated files should be in:
echo   %MOUNT_DIR%
echo   AttackGraph.pdf / AttackGraph.dot / AttackGraph.txt
exit /b 0

:normalize_mount_dir
if "%MOUNT_DIR%"=="." set "MOUNT_DIR=%SCRIPT_DIR%"
if "%MOUNT_DIR:~0,2%"==".\" set "MOUNT_DIR=%SCRIPT_DIR%\%MOUNT_DIR:~2%"
if not "%MOUNT_DIR:~1,1%"==":" set "MOUNT_DIR=%SCRIPT_DIR%\%MOUNT_DIR%"
exit /b 0

:load_kv_file
set "KV_FILE=%~1"
if not exist "%KV_FILE%" exit /b 0

for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%KV_FILE%") do (
  if not "%%~A"=="" (
    set "KEY=%%~A"
    set "VAL=%%~B"
    if /I "!KEY!"=="MULVAL_CONTAINER" if not "!VAL!"=="" set "CONTAINER=!VAL!"
    if /I "!KEY!"=="MULVAL_IMAGE" if not "!VAL!"=="" set "IMAGE=!VAL!"
    if /I "!KEY!"=="MULVAL_MOUNT_DIR" if not "!VAL!"=="" set "MOUNT_DIR=!VAL!"
    if /I "!KEY!"=="INPUT_FILE" if not "!VAL!"=="" set "INPUT_FILE=!VAL!"
    if /I "!KEY!"=="RULES_FILE" set "RULES_FILE=!VAL!"
  )
)
exit /b 0

:init_env
if exist "%ENV_FILE%" (
  echo .env already exists: %ENV_FILE%
  exit /b 0
)
copy /Y "%SCRIPT_DIR%\.env.example" "%ENV_FILE%" >nul
echo Created .env from .env.example
exit /b 0

:init_legacy_config
if exist "%LEGACY_CONFIG_FILE%" (
  echo Config already exists: %LEGACY_CONFIG_FILE%
  exit /b 0
)
(
  echo # Legacy config for mulval-docker.bat
  echo INPUT_FILE=sample-attack.P
  echo # RULES_FILE=rules.P
)> "%LEGACY_CONFIG_FILE%"
echo Created legacy config: %LEGACY_CONFIG_FILE%
exit /b 0
