# mulval-pylogic

将 MulVAL 风格的规则推理逻辑改写为 Python 库，输入仍使用 `.P` 文件，输出包含：

- `VERTICES.CSV`
- `ARCS.CSV`
- `AttackGraph.txt`
- `AttackGraph.pdf`

## 安装

```bash
pip install -e .
```

## 命令行使用

```bash
mulval-logic --input F:\mulval-docker\S2.P --rules F:\mulval-docker\rules5.P --output-dir F:\mulval-docker
```

## Python API 使用

```python
from pathlib import Path
from mulval_pylogic import LogicConfig, run_logic

result = run_logic(
    LogicConfig(
        input_file=Path(r"F:\mulval-docker\S2.P"),
        rules_file=Path(r"F:\mulval-docker\rules5.P"),
        output_dir=Path(r"F:\mulval-docker"),
    )
)

print(result.attackgraph_pdf)
```

## 输入格式

- 输入 `.P` 文件格式保持不变（如 `S2.P`）
- 规则 `.P` 文件格式保持不变（如 `rules5.P`）

## 说明

- 该实现是 Python 规则推理引擎，不依赖 MulVAL Docker 推理流程。
- 生成 PDF 依赖 Graphviz 的 `dot` 命令（请保证已安装并可执行）。
