# mulval-pylogic

`mulval-pylogic` 是一个纯 Python 的 MulVAL 风格推理库，输入仍然使用 `.P` 文件格式。

## 目录

- `pyproject.toml`
- `src/mulval_pylogic/`
  - `engine.py`：推理与图构建逻辑
  - `cli.py`：命令行入口
  - `__init__.py`：Python API 导出

## 安装

```powershell
cd python-lib
pip install -e .
```

## 命令行用法

```powershell
mulval-logic --input ..\S2.P --rules ..\rules5.P --output-dir ..\pylogic_out
```

参数：

- `--input`：输入场景文件（`.P`）
- `--rules`：规则文件（如 `rules5.P`）
- `--output-dir`：输出目录
- `--dot-bin`：可选，Graphviz `dot.exe` 路径

## Python API

```python
from pathlib import Path
from mulval_pylogic import LogicConfig, run_logic

result = run_logic(
    LogicConfig(
        input_file=Path(r"..\S2.P"),
        rules_file=Path(r"..\rules5.P"),
        output_dir=Path(r"..\pylogic_out"),
    )
)

print(result.vertices_csv)
print(result.arcs_csv)
print(result.attackgraph_txt)
print(result.attackgraph_pdf)
```

## 输出文件

- `VERTICES.CSV`
- `ARCS.CSV`
- `AttackGraph.txt`
- `AttackGraph.dot`
- `AttackGraph.pdf`

## 说明

- 布局方向为上下（Top-to-Bottom）
- 节点形状：`LEAF=box`、`AND=ellipse`、`OR=diamond`
- 目标是与 Docker 版 MulVAL 在“推理得到的节点和边”上保持一致
