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

## 代码审查整改计划 v2（2026-08-15）

本计划实现 `docs/spec.md` 的“安全与评测整改 v2”。依赖顺序为：先锁定共享契约，再并行修改三个互斥模块，最后由 Orchestrator 统一审查和验收。

```text
R0 规格、共享 DTO 与配置契约
  |-- R1 安全输入输出、完整配置、CLI 退出码
  |-- R2 风险域污点、控制流、路径守卫、歧义路由
  `-- R3 证据化 Agent、硬预算、结构化截断、报告与指标
          `-- R4 跨模块集成、中文文档、完整验收
```

### 锁定契约与文件所有权

- Contract Worker（指定共享契约所有者）：`src/aegisflow/contracts.py`、`src/aegisflow/config.py`、`tests/test_contracts.py`。先完成 `AnalysisResult`、配置硬上限、HTTPS/loopback 与 FDR 字段迁移；不得修改其他代码。
- Worker A：`src/aegisflow/cli.py`、`src/aegisflow/ingest/**`、`config/model.example.toml`、`tests/test_cli.py`、`tests/test_ingest.py`。实现安全输出、读取完整性、完整配置加载和退出矩阵；不得修改共享契约。
- Worker B：`src/aegisflow/analyzers/**`、`tests/test_analyzers.py` 及仅用于分析回归的 `tests/fixtures/**`。实现风险域 taint、保守控制流、路径守卫与真实歧义候选；不得修改共享契约。
- Worker C：`src/aegisflow/providers/**`、`src/aegisflow/workflow/**`、`src/aegisflow/reporting/**`、`src/aegisflow/benchmark/**`、`tests/test_providers.py`、`tests/test_workflow.py`、`tests/test_reporting.py`、`tests/test_benchmark.py`。实现证据门禁、硬预算、结构化截断、指标与摘要；不得修改共享契约。
- Orchestrator：只负责规格、任务、任务记忆、Worker 审查、冲突协调和最终验证。任何跨所有权修改必须先回报并重新分配。

跨 Worker 的内部接口锁定为：Worker C 在 `WorkflowResult` 增加 `agent_failures: tuple[str, ...]`（默认空元组，元素为稳定的非秘密原因码）；Worker A 只读取该字段，并在 `AppConfig.require_agent_success=True` 且字段非空时映射退出码 `4`。两个 Worker 均不得为此修改共享 Pydantic 契约或对方所有权文件。

接管记录：原 Worker B 在第三波执行期间因外部 Agent 服务余额不足而中断；其已落盘的分析器改动保留。经 Orchestrator 重新分配，已完成的 Worker C 临时接管 `src/aegisflow/analyzers/**` 与 `tests/test_analyzers.py` 的剩余反例修复，直至分析器交叉审查项关闭；这是一次明确的所有权迁移，不改变共享契约。

文档收口所有权：代码门禁通过后，Worker A 临时负责 `README.md` 与 `docs/**`（不改写 `docs/competition-code-review.md` 的原始审查证据，只可追加整改状态），同步 FDR、扫描完整性、严格 Agent、预算和残余风险的中文表述；不得再修改产品代码或测试。

供应链收口所有权：Supply Chain Worker 独占 `.github/**`、`uv.lock` 与根目录 `sbom.cdx.json`。使用现有 `pyproject.toml` 生成带哈希锁文件和 CycloneDX 1.5 SBOM，并建立 Linux/Windows、受支持 Python、pytest/Ruff、wheel 构建安装、CLI smoke、依赖审计与链接安全测试的 CI；不得修改产品代码、测试、文档或 `pyproject.toml`。

最终审查接管记录：发现公共 `write_report` 输出边界、无风险域标记反证、三类内联表达式和 ground-truth 退出码问题后，Worker A 临时接管 `src/aegisflow/cli.py` 与 `tests/test_cli.py` 的退出码修复；Worker C 临时接管 `src/aegisflow/reporting/**`、`src/aegisflow/workflow/**`、`src/aegisflow/analyzers/**` 及对应测试，完成最后四项 P1 的修复。原有 Worker 所有权以本次明确迁移为准。

由于并发上限为三个 Worker，Contract Worker 先完成 R0；其结束并通过契约测试后，原 Agent 复用为 Worker A，并与 Worker B、Worker C 并行。

### 集成检查点

1. R0：`python -m pytest -q tests/test_contracts.py`。
2. R1/R2/R3：各 Worker 运行其所有权范围内测试和 Ruff。
3. R4：Orchestrator 审查 diff，解决仅由契约迁移引起的跨模块编译问题，运行完整 pytest/Ruff/doctor/benchmark 和 offline/agent MockTransport CLI 集成测试。

### 风险处理

- Windows 链接权限不足：保留可在 Linux/有权限 Windows 执行的测试，不把 skip 当作已覆盖。
- 控制流范围过大：采用等价的分支环境与保守 join，不承诺完整跨过程或路径敏感分析。
- schema 迁移：只迁移审查确认错误的 FDR 字段并同步测试/文档，不增加未经批准的公共字段。
- 外部赛事证据：独立留出集、授权案例、真实 provider 和官方靶场不在本地代码整改中伪造；最终报告继续明确缺口。
