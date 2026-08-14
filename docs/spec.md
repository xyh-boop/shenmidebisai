# 规格说明：AegisFlow 证据驱动审计 Agent

## 状态

- 阶段：IMPLEMENT
- 状态：已实现并通过验证
- 方向批准日期：2026-08-14

## 目标

AegisFlow 是面向 Python 和 JavaScript/TypeScript 仓库的本地优先源代码安全审计 Agent。它结合确定性的候选发现、轻量污点证据图、对抗式 Agent 复核与成本感知路由，在不把每个源文件变成不透明模型提示词的前提下发现高风险漏洞。

产品面向安全研究人员、SRC 团队和比赛评委，同时满足三项需求：

1. 提供准确且可审查的漏洞证据；
2. 证明相对于原始静态候选的可衡量改进；
3. 提供可复现的延迟、准确率、模型成本和人工复核指标。

MVP 深入支持四类漏洞：

- 命令注入（`CWE-78`）；
- SQL 注入（`CWE-89`）；
- 路径遍历（`CWE-22`）；
- 不安全反序列化（`CWE-502`）。

## 设计假设

1. 目标仓库是不可信的只读数据。AegisFlow 绝不导入、执行、构建、安装或测试目标代码。
2. MVP 仅支持 Python 和 JavaScript/TypeScript。
3. 主要交互界面是 CLI，输出 JSON 和自包含 HTML 报告。
4. 离线模式具有确定性，不需要模型凭据或网络访问。
5. Agent 模式使用显式启用的兼容 OpenAI API 的服务端点，并且只发送受限、脱敏的证据片段。
6. 基准测试结论只适用于版本化样本集、记录的配置和记录的机器环境。
7. 四类漏洞的检测深度优先于增加更多浅层规则。
8. 自动生成的修复建议仅供参考；AegisFlow 不修改被扫描的源代码。

## Agent 工作流

```text
安全读取仓库
  -> 确定性候选发现
  -> 构建本地证据图
  -> 置信度与风险评分
  -> 成本感知路由
       -> 证据完整时自动确认
       -> 风险较低或证据有歧义时进入人工复核
       -> 高风险且有歧义的候选进入对抗式复核
            -> Verifier：支持性证据
            -> Critic：净化处理、约束、常量和不可达路径
            -> Arbiter：结构化最终决策
  -> 生成稳定的发现指纹
  -> 输出 JSON / HTML / 基准指标
```

Agent 角色是受契约约束的处理阶段，不是自由发挥的人格。无效的模型输出会被拒绝，且不能影响漏洞发现结果。

## 用户故事

- 研究人员可以用一条命令扫描仓库，并获得带有精确路径、行号范围、CWE 标签、证据图和修复建议的优先级发现。
- 审查人员可以检查来源、传播、净化处理、约束和汇点节点，而不是接受没有依据的模型断言。
- 评委可以比较原始候选与最终发现，并查看召回率、假阳性率、首个高危发现时间、每条确认发现的成本和人工复核比例。
- 操作者可以完全离线运行，也可以为 Agent 模式设置请求数、令牌和美元硬限制。
- 测试人员可以基于独立真值清单和稳定发现指纹复现基准成绩。

## 功能需求

### 安全读取

- 在显式指定的根目录下发现 `.py`、`.js`、`.jsx`、`.ts` 和 `.tsx` 文件。
- 默认忽略依赖、版本控制、缓存、构建、覆盖率、生成文件和产物目录。
- 绝不跟随符号链接；拒绝解析后位于根目录之外的路径。
- 支持配置文件数量、总字节数和单文件字节数限制。
- 对二进制文件或无法解码的文件跳过，并输出结构化诊断信息。
- 统计扫描文件和逻辑源代码行数，不能因忽略内容而虚增指标。

### 候选发现

- Python 使用标准库 AST 解析。
- JavaScript/TypeScript 使用 Tree-sitter 解析，绝不执行代码。
- 每条规则生成带稳定定位信息和初始证据的类型化 `Candidate` 对象。
- 规则既包含正向信号，也包含对常量、参数化查询、安全路径约束和安全反序列化器的明确抑制条件。

### 证据图

- 将每条发现建模为节点和有向边。
- 节点类型：`source`、`propagation`、`sanitizer`、`constraint`、`sink`、`context`。
- 边类型：`flows_to`、`sanitized_by`、`guarded_by`、`derived_from`。
- 每条确认或可能的发现至少包含一个汇点和一个支持性证据节点。
- 注入和路径遍历发现必须包含 Source-to-Sink 路径，除非该汇点本身具有独立且确定的危险性。

### 成本感知路由

- 确定性计算证据完整度、可利用性和初始置信度。
- 对证据完整且置信度高的候选无需模型调用，直接确认。
- 对已证明是安全常量或命中已识别净化器的候选自动拒绝。
- 仅将高风险且有歧义的候选送入对抗式复核。
- 每次请求前执行模型请求数、提示词令牌、补全令牌、上下文字节和预估美元预算检查。
- 记录每个候选被路由、跳过、确认、拒绝或留给人工复核的原因。

### 对抗式复核

- `Verifier` 返回结论、支持性节点 ID、原因代码和简要依据。
- `Critic` 独立返回反证节点 ID、原因代码和简要依据。
- `Arbiter` 只能使用已校验的图节点和之前的结构化决策。
- 指示模型的源码注释必须作为不可信证据引用，不能改变系统指令。
- 无效 JSON、未知节点引用、超时或预算耗尽都只能得到 `needs_review`，绝不能静默确认为漏洞。

### 报告

- JSON 是规范报告；HTML 从同一份已校验的报告封装渲染而来。
- HTML 必须自包含、响应式，并转义所有由仓库控制的内容。
- 报告展示严重性汇总、置信度、证据图、Agent 决策时间线、支持性证据与反证、路由原因、延迟、令牌用量、预估成本和人工复核状态。
- 稳定的内容排序和发现指纹使重复运行结果可比较。

### 基准测试

- 分别维护演示样本集和回归样本集。
- 在可行的情况下，每类漏洞都包含两种支持语言的漏洞样例和安全近似样例。
- 真值存放在独立清单中；预期发现不能嵌入源代码注释。
- 评分以定位为依据。真阳性必须匹配规则 ID、规范化路径和重叠行号范围。
- 重复指纹只计一次。
- 离线指标是主要可复现成绩；Agent 辅助前后指标单独报告。

## 公共契约

共享字段和枚举值已经锁定。未经批准的规格更新，Worker Agent 不得重命名或扩展它们。

```python
class EvidenceNode(BaseModel):
    node_id: str
    kind: Literal["source", "propagation", "sanitizer", "constraint", "sink", "context"]
    path: str
    line: int
    symbol: str | None
    snippet: str
    description: str

class EvidenceEdge(BaseModel):
    source_id: str
    target_id: str
    relation: Literal["flows_to", "sanitized_by", "guarded_by", "derived_from"]

class AgentDecision(BaseModel):
    agent: Literal["scout", "tracer", "verifier", "critic", "arbiter"]
    verdict: Literal["confirm", "reject", "needs_review"]
    confidence: float
    reason_codes: list[str]
    supporting_node_ids: list[str]
    counterevidence_node_ids: list[str]
    rationale: str
    latency_ms: int

class Finding(BaseModel):
    finding_id: str
    rule_id: str
    cwe: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    disposition: Literal["confirmed", "likely", "rejected", "needs_review"]
    language: Literal["python", "javascript", "typescript"]
    path: str
    start_line: int
    end_line: int
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    decisions: list[AgentDecision]
    remediation: str

class RunMetrics(BaseModel):
    files_scanned: int
    lines_scanned: int
    elapsed_ms: int
    time_to_first_high_ms: int | None
    candidates_total: int
    findings_confirmed: int
    findings_rejected: int
    human_review_required: int
    model_requests: int
    prompt_tokens: int
    completion_tokens: int
    estimated_cost_usd: float
```

每个报告封装都包含 `schema_version`、`tool_version`、`run`、`metrics`、`findings` 和 `diagnostics`。仓库路径统一使用 `/` 分隔符。`finding_id` 是由规则 ID、规范化路径、漏洞行号范围和规范化证据身份计算出的稳定 SHA-256 摘要。

## CLI 契约

```powershell
# 安装
python -m pip install ".[dev]"

# 校验环境
aegisflow doctor

# 查看规则覆盖范围
aegisflow rules --format table

# 确定性的离线扫描
aegisflow scan . --mode offline --format html --output .\artifacts\report.html

# 成本受限的 Agent 扫描
aegisflow scan . --mode agent --model-config .\config\model.example.toml --max-requests 8 --max-cost-usd 0.50 --output .\artifacts\report.html

# 可复现基准测试
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json

# 验证
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

退出码：

- `0`：完成，且没有发现达到配置阈值的漏洞；
- `1`：完成，且至少有一条发现达到配置阈值；
- `2`：参数或配置无效；
- `3`：输入或解析失败，无法完成可信扫描；
- `4`：必需的 Agent 模式失败或耗尽了强制预算。

## 技术栈

- Python 3.11+
- Pydantic 2.x：共享契约
- Typer 与 Rich：CLI 输出
- Python AST 与 Tree-sitter 语言包：代码解析
- Jinja2：自包含报告
- HTTPX：可选的兼容 OpenAI API 服务提供方
- pytest 与 Ruff：验证工具

默认测试使用虚假的服务提供方传输，既不需要凭据，也不需要网络。

## 项目结构

```text
src/aegisflow/
  cli.py                  CLI 与退出码映射
  contracts.py            锁定的 DTO 与枚举
  config.py               限制、路由和服务提供方配置
  ingest/                 安全的仓库发现与加载
  analyzers/              解析器、规则和本地证据追踪
  workflow/               评分、路由、复核和仲裁
  providers/              兼容 OpenAI API 的适配器与预算统计
  reporting/              JSON、HTML 和指标
  benchmark/              真值加载与评分
tests/                    单元、契约、集成和安全测试
benchmarks/               演示/回归样例与真值
docs/                     规格、架构、威胁模型和演示脚本
tasks/                    SDD 计划和任务清单
config/                   不含密钥的示例
artifacts/                生成的输出，不纳入版本控制
```

## 代码风格

- 公共边界使用类型标注，工作流阶段之间使用 Pydantic 校验。
- 使用小型确定性函数；副作用隔离在读取、服务提供方和报告适配器中。
- 文件、候选、图节点、决策和发现保持稳定排序。
- 预期失败使用结构化诊断信息；不可恢复的故障使用异常。
- 注释只记录安全不变量和不明显的分析权衡。

```python
def route_candidate(candidate: Candidate, budget: BudgetState) -> RoutingDecision:
    if candidate.proven_safe:
        return RoutingDecision(action="reject", reason="recognized_sanitizer")
    if candidate.evidence_complete and candidate.confidence >= 0.90:
        return RoutingDecision(action="confirm", reason="complete_local_evidence")
    if candidate.severity in {Severity.CRITICAL, Severity.HIGH} and budget.can_review():
        return RoutingDecision(action="agent_review", reason="high_risk_ambiguity")
    return RoutingDecision(action="needs_review", reason="insufficient_evidence")
```

## 测试策略

- 为路径包含、限制、脱敏、AST 匹配、证据图、置信度校准、路由、预算统计、稳定指纹、转义和基准计算编写单元测试。
- 每条规则都提供正向样例和安全近似的负向样例。
- 为所有 Agent 阶段输出和未知图节点引用编写契约测试。
- 使用注入时钟和规范化易变字段编写 Golden JSON 测试。
- 编写从仓库扫描到 JSON、HTML 生成的 CLI 集成测试。
- 编写符号链接逃逸、语法错误、二进制文件、超大输入、HTML 注入、注释中的提示词注入和密钥泄露安全测试。
- 服务提供方测试使用虚假的 HTTP 传输，覆盖超时、格式错误响应、重试和预算耗尽。
- 可重复性测试要求相同输入和配置的两次离线扫描产生完全相同的规范化发现。

## 边界

### 始终执行

- 将仓库内容和模型输出视为不可信输入。
- 验证每个解析后路径仍位于选定根目录内。
- 在 HTML 中转义所有仓库内容。
- 根据锁定契约校验每次工作流状态转换。
- 在调用前执行模型预算检查，并对有限上下文进行脱敏。
- 记录基准配置、运行时版本和原始指标。
- 交付前运行测试、Ruff 检查和基准测试。

### 先征得同意

- 修改共享契约字段、枚举、CLI 命令或报告模式。
- 在批准的技术栈之外增加运行时依赖。
- 将真实仓库片段发送给外部服务提供方。
- 增加语言、漏洞类别、托管服务、数据库或主动扫描能力。

### 严禁

- 执行、导入、构建、安装或测试被扫描仓库。
- 生成或运行漏洞利用载荷或 PoC。
- 持久化密钥、原始环境变量、API Key 或会话数据。
- 跟随扫描根目录之外的符号链接。
- 将基准分数宣称为通用的真实世界准确率。
- 为提高指标而削弱测试或修改真值。

## 成功标准

1. `aegisflow doctor`、`rules`、`scan` 和 `benchmark` 能按文档运行并输出结果。
2. 离线模式无需凭据或网络即可扫描 Python 与 JavaScript/TypeScript 样例。
3. 所有确认发现都包含汇点、证据节点、有效图边、Agent 决策、精确定位、CWE、置信度和修复建议。
4. 基准测试至少包含四类漏洞的 16 个漏洞/安全样例，并在声明的样本集上达到至少 85% 召回率和不超过 15% 的假阳性率。
5. 在记录的开发机器上，内置样本集的离线扫描在 10 秒内完成，并记录首个高危发现时间。
6. 两次离线运行产生完全相同的规范化发现和指纹。
7. Agent 模式不超过配置的请求或费用预算，并将无效响应降级为 `needs_review`。
8. 报告展示审计量、Precision、Recall、假阳性率、F1、耗时、首个高危发现时间、复核减少量、令牌数和预估成本。
9. HTML 报告能安全渲染恶意片段，并适配桌面和移动视口，不出现控件或文本重叠。
10. 默认 pytest 套件和 Ruff 检查通过，核心安全、路由、基准和报告路径有测试覆盖。
11. 项目包含中文 README、架构说明、威胁模型、基准测试方法和五分钟演示脚本。
12. 任何操作都不会向被扫描仓库写入内容或执行其中代码。

## 待解决问题

没有阻塞性问题。用户已于 2026-08-14 批准此优化方向。实时模型服务提供方仍为可选项，可在演示时通过兼容 OpenAI API 的配置选择。
