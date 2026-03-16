# MulVAL Attack Graph (Docker + Python)

这个仓库包含两部分：

1. Docker 运行方式（原始 MulVAL 流程，配合 `mulval-docker.bat`）
2. 纯 Python 推理库（已单独放到 `python-lib/`）

## 目录结构

- `docker-compose.yml`：MulVAL 容器编排
- `mulval-docker.bat`：Windows 一键驱动脚本
- `S2.P`、`rules5.P`：示例输入与规则文件
- `python-lib/`：独立 Python 项目（`src` 布局）

## Docker 用法（Windows）

1. 安装并启动 Docker Desktop
2. 在仓库根目录运行 `mulval-docker.bat`
3. 在脚本里可配置输入和规则文件名

## Python 用法

Python 项目说明见：

- [`python-lib/README.md`](python-lib/README.md)

快速开始：

```powershell
cd python-lib
pip install -e .
mulval-logic --input ..\S2.P --rules ..\rules5.P --output-dir ..\pylogic_out
```

## 输出文件

无论 Docker 还是 Python，都会生成以下核心文件：

- `VERTICES.CSV`
- `ARCS.CSV`
- `AttackGraph.txt`
- `AttackGraph.pdf`

其中 Python 版本已验证在多组场景下可对齐 Docker 的“节点和边推理结果”。
