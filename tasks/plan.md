# AegisFlow 实施计划

## 目标

根据 `docs/spec.md` 交付已批准的 AegisFlow MVP：安全的本地读取、四类深度漏洞分析、证据图、成本感知路由、对抗式复核契约、确定性的 JSON/HTML 报告，以及可复现的基准测试。

## 依赖关系

```text
P0 共享包 + 契约 + 配置
  |-- P1 安全仓库读取
  |-- P2 Python 与 JS/TS 候选分析
  |     `-- P3 证据评分与成本感知工作流
  |            `-- P4 可选服务提供方与对抗式复核
  |-- P5 报告与基准评分
  `-- P6 CLI 集成
         `-- P7 样例、文档、端到端验证
```

## 锁定契约

`docs/spec.md` 中的 DTO 和枚举值是权威定义。实现只能在 `src/aegisflow/contracts.py` 中增加内部模型（`SourceFile`、`Candidate`、`RoutingDecision`、`Diagnostic`、`ReportEnvelope`、`BenchmarkResult`、`BudgetState`），不能修改现有公共字段名和枚举值。

要求的可调用边界：

```python
discover_repository(root: Path, limits: ScanLimits) -> IngestResult
analyze_sources(sources: Sequence[SourceFile], config: AnalysisConfig) -> list[Candidate]
build_finding(candidate: Candidate, policy: RoutingPolicy) -> Finding
review_candidate(candidate: Candidate, provider: ReviewProvider, budget: BudgetState) -> list[AgentDecision]
render_json(report: ReportEnvelope) -> str
render_html(report: ReportEnvelope) -> str
score_benchmark(report: ReportEnvelope, truth: GroundTruth) -> BenchmarkResult
```

所有跨模块路径都必须规范化为仓库相对 POSIX 字符串。公共边界返回的列表必须稳定排序。

## 实施阶段

### 阶段 0：基础

- 创建包清单、依赖版本、包元数据、共享 DTO、限制和配置。
- 验证严格 DTO 校验、图引用校验、置信度边界和确定性序列化。

检查点：依赖模块开始前，契约测试必须通过。

### 阶段 1：安全输入与分析

- 实现带忽略策略、路径包含校验、文件/字节限制、二进制检测和诊断信息的安全仓库发现。
- 实现 Python AST 候选发现和轻量 Source-to-Sink 追踪。
- 实现 JS/TS Tree-sitter 候选发现，使用相同的四条规则 ID 和通用证据语义。
- 增加正向样例与安全近似的负向单元样例。

检查点：分析器与读取模块测试通过，且不会执行目标代码。

### 阶段 2：Agent 工作流与输出

- 实现证据完整度评分、本地确认/拒绝、路由、预算统计和对抗式决策校验。
- 在协议后实现兼容 OpenAI API 的复核传输，并使用虚假传输进行测试。
- 实现规范 JSON、经过转义的自包含 HTML、基准计算和稳定指纹。
- 集成 CLI 命令与退出码映射。

检查点：端到端离线扫描能够生成有效 JSON 和 HTML。

### 阶段 3：比赛交付包

- 构建至少 16 个漏洞/安全基准样例和独立真值清单。
- 生成基准产物，确认声明的召回率/假阳性率阈值。
- 增加 README、架构、威胁模型、基准测试方法和五分钟演示脚本。
- 执行 Ruff、pytest、可重复性、恶意 HTML 和移动/桌面报告检查。

检查点：所有成功标准都有命令或产物证据。

## 并行工作与文件所有权

### 第一波

- Foundation Worker 负责：`pyproject.toml`、`.gitignore`、`src/aegisflow/__init__.py`、`src/aegisflow/contracts.py`、`src/aegisflow/config.py`、`tests/test_contracts.py`。
- Ingestion Worker 负责：`src/aegisflow/ingest/**`、`tests/test_ingest.py`。
- Analysis Worker 负责：`src/aegisflow/analyzers/**`、`tests/test_analyzers.py`。

Ingestion 和 Analysis 可以读取锁定规格，但只能在 Foundation 暴露契约后进行最终集成。它们不能编辑共享文件。

### 第二波

- Workflow Worker 负责：`src/aegisflow/workflow/**`、`src/aegisflow/providers/**`、`tests/test_workflow.py`、`tests/test_providers.py`。
- Reporting Worker 负责：`src/aegisflow/reporting/**`、`src/aegisflow/benchmark/**`、`tests/test_reporting.py`、`tests/test_benchmark.py`。
- Delivery Worker 负责：`src/aegisflow/cli.py`、`benchmarks/**`、`config/**`、`README.md`、`docs/architecture.md`、`docs/threat-model.md`、`docs/benchmark.md`、`docs/demo-script.md`、`tests/test_cli.py`。

Worker 不得编辑其他 Worker 的所有权范围。共享契约变更必须先报告给 Orchestrator，并在修改代码前完成规格更新。

## 风险与缓解措施

- Tree-sitter 安装：固定有 wheel 支持的包版本；`doctor` 明确报告 JS/TS 支持是否可用。
- 轻量 JS/TS 追踪：将结论限制在本地语法和赋值流，并使用安全近似负向样例。
- 模型不确定性：离线基准作为规范基线；模型输出经过模式校验并单独报告。
- 样例过拟合：区分演示和回归样本集，并加入结构相似的安全样例。
- HTML 注入：使用 Jinja 自动转义，并加入包含恶意路径/片段的测试。
- 截止时间压力：四类漏洞与完整证据/报告能力优先于增加规则或 UI 功能。

## 验证命令

```powershell
python -m pip install ".[dev]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
aegisflow doctor
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```
