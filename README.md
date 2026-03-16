# MulVAL Attack Graph Docker (Windows)

一个面向 Windows 的 MulVAL 攻击图 Docker 启动器，提供两种用法：

1. 双击/命令行运行 `mulval-docker.bat`（推荐）
2. 使用 `.env` + `docker-compose.yml`（环境清单式配置）

## 适用场景

- 想快速在本机跑 MulVAL 攻击图
- 想把 `input/rules`、容器名、挂载目录放在配置文件里统一管理

## 目录结构

```text
.
├─ mulval-docker.bat
├─ docker-compose.yml
├─ .env.example
├─ sample-attack.P
└─ README.md
```

## 前置要求

- Windows 10/11
- Docker Desktop（已启动）

## 快速开始（BAT 驱动）

1. 复制配置文件：

```bat
copy .env.example .env
```

2. 按需修改 `.env`：

```env
MULVAL_CONTAINER=mulval-attackgraph
MULVAL_IMAGE=wilbercui/mulval
MULVAL_MOUNT_DIR=.
INPUT_FILE=sample-attack.P
# RULES_FILE=rules5.P
```

3. 运行：

```bat
mulval-docker.bat
```

默认会执行 `run`，并在当前目录输出：

- `AttackGraph.pdf`
- `AttackGraph.dot`
- `AttackGraph.txt`

## 常用命令

```bat
mulval-docker.bat status
mulval-docker.bat up
mulval-docker.bat recreate
mulval-docker.bat run
mulval-docker.bat run your-input.P your-rules.P
mulval-docker.bat shell
mulval-docker.bat down
```

## 环境清单式安装（Compose）

1. 准备 `.env`（由 `.env.example` 复制）
2. 启动容器：

```bat
docker compose up -d
```

3. 执行 MulVAL：

```bat
docker exec mulval-attackgraph bash -lc "cd /input && graph_gen.sh -v sample-attack.P"
```

4. 关闭容器：

```bat
docker compose down
```

## 配置说明

- `MULVAL_CONTAINER`：容器名
- `MULVAL_IMAGE`：镜像名
- `MULVAL_MOUNT_DIR`：挂载到 `/input` 的本机目录
- `INPUT_FILE`：默认输入文件
- `RULES_FILE`：默认规则文件（可选）

如果你修改了 `MULVAL_MOUNT_DIR`，执行一次：

```bat
mulval-docker.bat recreate
```

## 故障排查

- 提示 Docker 未启动：先打开 Docker Desktop，等待引擎就绪后重试
- 双击后窗口一闪而过：用 `cmd` 打开目录后手动运行 `mulval-docker.bat` 查看报错
- `Input file not found`：确认文件在 `MULVAL_MOUNT_DIR` 指向的目录中
