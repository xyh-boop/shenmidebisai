# AegisFlow 任务清单

- [x] T01：创建包基础与锁定契约
  - 验收：DTO、枚举、图校验、配置和稳定序列化与 `docs/spec.md` 一致。
  - 验证：`python -m pytest -q tests/test_contracts.py`
  - 文件：`pyproject.toml`、`.gitignore`、`src/aegisflow/__init__.py`、`src/aegisflow/contracts.py`、`src/aegisflow/config.py`、`tests/test_contracts.py`

- [x] T02：实现安全仓库读取
  - 验收：路径包含、忽略列表、限制、二进制/编码处理和结构化诊断生效，且不会跟随符号链接。
  - 验证：`python -m pytest -q tests/test_ingest.py`
  - 文件：`src/aegisflow/ingest/**`、`tests/test_ingest.py`

- [x] T03：实现四类 Python 与 JS/TS 候选分析
  - 验收：分析器针对命令注入、SQL 注入、路径遍历和不安全反序列化输出类型化候选与证据，并抑制安全近似样例。
  - 验证：`python -m pytest -q tests/test_analyzers.py`
  - 文件：`src/aegisflow/analyzers/**`、`tests/test_analyzers.py`

- [x] T04：实现评分、路由、预算与对抗式复核
  - 验收：确定性路由正确处理确认/拒绝/复核路径；服务提供方输出和图引用经过校验；预算不能被超出。
  - 验证：`python -m pytest -q tests/test_workflow.py tests/test_providers.py`
  - 文件：`src/aegisflow/workflow/**`、`src/aegisflow/providers/**`、`tests/test_workflow.py`、`tests/test_providers.py`

- [x] T05：实现规范报告与基准评分器
  - 验收：生成稳定 JSON、经过转义的响应式 HTML、基于定位且去重的评分结果和所有必需指标。
  - 验证：`python -m pytest -q tests/test_reporting.py tests/test_benchmark.py`
  - 文件：`src/aegisflow/reporting/**`、`src/aegisflow/benchmark/**`、`tests/test_reporting.py`、`tests/test_benchmark.py`

- [x] T06：集成 CLI、基准样本集与交付文档
  - 验收：`doctor`、`rules`、`scan` 和 `benchmark` 可用；至少存在 16 个样例；所有要求的文档均已提供。
  - 验证：`python -m pytest -q tests/test_cli.py`；运行文档中的 CLI 命令。
  - 文件：`src/aegisflow/cli.py`、`benchmarks/**`、`config/**`、`README.md`、`docs/architecture.md`、`docs/threat-model.md`、`docs/benchmark.md`、`docs/demo-script.md`、`tests/test_cli.py`

- [x] T07：集成与比赛验收
  - 验收：完整 pytest 和 Ruff 门禁通过；规范化离线输出可重复；基准达到声明目标；HTML 通过桌面/移动检查。
  - 验证：运行 `tasks/plan.md` 中的命令并检查报告截图。
  - 文件：缺陷修复仅限对应模块；生成产物位于 `artifacts/**`。
