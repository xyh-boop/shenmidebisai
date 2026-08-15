# AegisFlow 参赛符合性、架构与代码安全审查报告

> 审查日期：2026-08-15  
> 审查范围：`src/`、`tests/`、`benchmarks/`、`config/`、`README.md`、`docs/`、`pyproject.toml`  
> 审查方式：源码静态审查、反例验证、CLI 验收、测试与规范检查  
> 本报告区分“已确认缺陷”和“残余风险”；未复现的问题不表述为确定漏洞。

## 1. 执行结论

**当前版本是结构完整的源码审计 MVP，但还不具备严谨宣称“满足 Agent+ 攻防挑战赛要求”或“可直接进入靶场”的证据。**

项目已经实现安全读取、Python AST/JavaScript Tree-sitter 分析、Source-to-Sink 证据、离线决策、可选模型复核、JSON/HTML 报告和 benchmark。基础工程质量较好，现有测试与 Ruff 均通过。

但是，本轮审查确认了会影响安全性、检测正确性和参赛指标真实性的问题：

1. 推荐报告路径可通过符号链接或 Windows 重解析点逃逸，存在覆盖仓库外文件的风险。
2. 默认真实扫描产生的候选全部被本地自动确认，`agent` 模式不会调用 Verifier/Critic/Arbiter；比赛核心 Agent 能力目前只有合成单元测试证据。
3. 解析失败、读取错误和资源上限截断可能被当作成功扫描，形成 fail-open。
4. 通用净化状态、控制流遍历和路径守卫判断存在可复现漏报。
5. 模型可在缺少有效反证节点时将高危候选降为 `rejected`，且 `--fail-on` 不再拦截。
6. “误报率”和“首个高危发现时间”的当前计算口径错误，不能直接用于赛事量化证明。

因此建议将当前状态标记为：**功能原型可演示，安全与评测整改中，尚未完成靶场验收。**

## 2. 验证结果

| 检查项 | 实际结果 | 结论 |
|---|---:|---|
| `python -m pytest -q` | 81 passed, 2 skipped | 主测试通过；两个符号链接安全分支未执行 |
| `python -m ruff check .` | All checks passed | 静态规范通过 |
| `python -m ruff format --check .` | 32 files already formatted | 格式通过 |
| `python -m aegisflow.cli doctor` | Python 3.11.9，parsers available | 运行时与解析器可导入 |
| CLI 入口 | `doctor/rules/scan/benchmark` 可用 | 命令入口正常 |
| 内置 benchmark | Precision/Recall/F1 1.000 | 仅证明当前 16 个内置样例，不代表真实项目 |

跳过项位于 `tests/test_ingest.py:164` 和 `tests/test_ingest.py:181`，原因是当前 Windows 账户没有创建符号链接的权限（WinError 1314）。恰好未执行的是与路径逃逸相关的安全测试，因此不能用“81 项通过”推导链接处理已得到完整验证。

## 3. 严重度定义

- **P0**：可能造成仓库边界外数据破坏，或直接破坏安全工具的核心信任边界；提交前必须修复。
- **P1**：导致稳定漏报、错误成功状态、核心功能不可达或参赛指标失真；提交前应修复。
- **P2**：影响健壮性、可复现性、维护性或特定场景安全；应纳入本轮整改。
- **P3**：需要进一步威胁建模或环境验证的残余风险，不作为已确认漏洞。

## 4. 已确认缺陷

### P0-1：报告输出可经链接逃逸并覆盖仓库外文件

**证据**：`src/aegisflow/cli.py:103` 的 `_guard_output` 先对输出执行 `resolve()`。如果仓库中的 `artifacts`、`.artifacts` 或报告文件是指向仓库外的符号链接/重解析点，解析后的路径位于 root 外，逻辑会直接放行。随后 `src/aegisflow/reporting/__init__.py:449` 使用 `Path.write_text()` 跟随链接写入。`benchmark` 在 `src/aegisflow/cli.py:329` 也直接写入路径。

**影响**：扫描不可信仓库时，攻击者可诱导工具覆盖当前用户有权限写入的仓库外文件。检查与写入之间还存在 TOCTOU 窗口。该行为与“将仓库视为不可信数据”的核心安全定位冲突。

**修改要求**：

- 拒绝输出路径任一既有组件中的 symlink、junction 和 reparse point。
- 使用不跟随链接的安全创建方式；可行时使用目录句柄、`O_NOFOLLOW` 或 Windows 等价机制。
- 在同目录创建临时文件，完整写入并 `fsync` 后原子替换；替换前重新校验目标身份。
- `scan` 和 `benchmark` 共用同一安全输出组件。
- 增加目录链接、文件链接、junction、扫描过程中替换目标和仓库内非允许输出路径测试；至少在 Linux 与具备链接权限的 Windows CI 中执行。

**验收标准**：上述链接/竞态用例不得修改仓库外目标；CLI 返回受控错误码并报告具体诊断。

### P1-1：默认 Agent 复核路径在真实扫描中不可达

**证据**：`src/aegisflow/analyzers/base.py:248` 只为仍然 tainted 且具有 source/sink 证据的 Trace 生成 Candidate；Python 和 JavaScript 分析器赋予候选约 `0.94-0.98` 的固定置信度（`src/aegisflow/analyzers/python.py:148`、`src/aegisflow/analyzers/javascript.py:157`）。默认 `auto_confirm_confidence=0.90`，`src/aegisflow/workflow/engine.py:67` 会直接确认这些候选。本轮对内置 fixture 的 8 个候选验证结果全部为 `confirm`，模型请求数为 0。

现有 `tests/test_workflow.py:171` 通过手工构造低置信 Candidate 触发复核，不能证明 CLI 的真实 analyzer -> workflow 路径会调用模型。

**影响**：代码中虽然存在 Verifier/Critic/Arbiter，但默认 `agent` 模式与离线模式在真实内置输入上的决策路径相同。无法据此证明模型提升、成本控制或 Agent 全流程已经落地。

**修改要求**：

- 重新定义证据完整度与置信度；函数参数不能自动等价于已证实外部可控输入。
- 为真实存在歧义的候选保留 `agent_review` 路由，不用人为降低所有候选分数来制造请求。
- 增加 CLI 级 Agent 集成测试，使用 MockTransport 验证真实 fixture 至少触发一次完整三阶段请求。
- 报告同时给出离线结论、模型增量结论、请求数、失败数、`needs_review` 数和成本。

**验收标准**：至少一个非合成、可解释的真实歧义案例从 analyzer 进入三阶段复核；offline/agent 对照结果可复现。

### P1-2：解析失败和不完整扫描采用 fail-open

**证据**：`src/aegisflow/analyzers/__init__.py:15` 捕获 Python `SyntaxError/UnicodeError/ValueError` 后直接跳过；`src/aegisflow/analyzers/javascript.py:63` 遇到 Tree-sitter `root.has_error` 返回空列表，均没有分析诊断。`src/aegisflow/ingest/repository.py:171` 对读取失败、竞态和配额问题记录 diagnostics 后继续。`src/aegisflow/cli.py:296` 只按 findings 判断退出状态，没有检查扫描完整性。

**影响**：语法错误文件、权限不可读目录或超出 `max_files/max_total_bytes` 后面的漏洞可以被静默漏掉，最终仍可能得到“0 finding、exit 0”。自动化系统无法区分“确认没有漏洞”和“文件没有被成功分析”。

**修改要求**：

- 分析器返回统一的 `AnalyzerResult(findings/candidates, diagnostics, completeness)`。
- 报告增加 `scan_complete`、`files_skipped`、`parse_errors`、`limits_hit` 和未分析路径清单。
- 默认遇到 ERROR 级诊断或任何解析失败返回退出码 3；如需容忍，应提供显式 `--allow-incomplete`。
- 对 malformed Python/JS、不可读文件/目录、配额截断和扫描期间文件变化增加 CLI 集成测试。

### P1-3：净化状态跨漏洞域复用造成稳定漏报

**证据**：通用 `Trace` 只有单一 `tainted` 状态；`src/aegisflow/analyzers/base.py:190` 的 `sanitize` 将其整体设为 false。Python 中 `json.loads`/安全 YAML 加载和 `basename`（`src/aegisflow/analyzers/python.py:203`、`:217`），以及 JavaScript 的 `JSON.parse`、`path.basename`（`src/aegisflow/analyzers/javascript.py:227`）均会影响所有 sink。

已复现的漏报类型包括：

- `json.loads(request.data)` 的字段随后进入文件路径 sink。
- `os.path.basename(user_input)` 的结果随后进入命令执行 sink。
- JavaScript `JSON.parse(request.body)` 的字段随后进入文件读取 sink。

JSON 安全解析只说明“反序列化动作本身安全”，不说明解析出的字符串对路径、命令或 SQL 安全；`basename` 也不能净化命令注入。

**修改要求**：将 taint 与 sanitizer 按风险域建模，例如 `command/sql/path/deserialization`；sanitizer 只能抑制对应域。为每个 sanitizer 增加同域安全用例和跨域不安全用例。

### P1-4：控制流与 AST 遍历不完整造成漏报和误报

**已确认问题**：

- Python `with/async with` 只处理 context expression，没有递归 body（`src/aegisflow/analyzers/python.py:60`、`:406`）；`with ...: os.system(user)` 不产生候选。
- Python `match` 等复合语句缺少完整递归。
- Python `try` 分支环境未可靠合并；`return/raise` 后不可达语句仍可能继续扫描，造成误报。
- JavaScript `if/else` 共用并顺序修改同一个环境（`src/aegisflow/analyzers/javascript.py:78`），一个分支的安全赋值可以覆盖另一分支的 taint。
- JavaScript 变量声明快捷路径可能跳过赋给变量的箭头函数参数污点。

**修改要求**：构建显式 CFG 或等价的分支状态系统；每个分支使用独立环境并保守 join；支持所有复合语句；处理终止语句后的不可达性。增加 `with/match/try/finally`、双分支合并、箭头函数、早退和不可达代码测试。

### P1-5：路径守卫的极性判断错误，可抑制真实路径遍历

**证据**：`src/aegisflow/analyzers/python.py:431` 只检查条件中是否存在 `is_relative_to` 且 if body 末尾为 `Raise/Return`，没有验证条件的否定方向、比较对象或通过分支。如下逻辑会被错误标记为安全约束：

```python
if candidate.is_relative_to(base):
    raise ValueError("reject inside path")
candidate.read_text()
```

**修改要求**：只在已证明“位于 base 外时终止，位于 base 内时继续”的条件下抑制 finding；校验 `resolve`、同一 base 和控制流方向。复杂布尔表达式无法证明时应保守保留候选。

### P1-6：模型可以在没有有效反证时隐藏高危候选

**证据**：`src/aegisflow/providers/review.py:57` 主要验证 role、verdict、reason code 和节点 ID 是否存在，不要求 `REJECT` 必须引用 sanitizer/constraint 类型的反证节点。`src/aegisflow/workflow/engine.py:188` 接受 Arbiter 的 `REJECT` 后将 finding 设为 `rejected`；`src/aegisflow/cli.py:296` 的 `--fail-on` 随后忽略它。

**影响**：提示注入、模型错误或受损 provider 可以输出格式合法但语义无依据的 reject，使本地高危候选不再触发 CI 阈值。

**修改要求**：

- 模型不得单独降低确定性本地基线；至少保留原始本地结论。
- reject 必须引用经类型校验的 sanitizer/constraint counterevidence，并满足 Verifier/Critic/Arbiter 一致性规则。
- 无反证、空引用或引用普通 source/sink 节点的 reject 一律降为 `needs_review`。
- 增加源码提示注入、受损 provider、合法 JSON 但无证据 reject 的对抗测试。

### P1-7：Agent endpoint 允许公网明文 HTTP

**证据**：`src/aegisflow/config.py:78` 接受 `http` 和 `https`；`src/aegisflow/providers/review.py:314` 会向该地址发送 Bearer API key 和证据片段。

**影响**：误配公网 HTTP endpoint 时，API key、文件路径和脱敏后的源码可被窃听或篡改。

**修改要求**：默认只允许 HTTPS；只对 loopback 调试提供显式 `allow_insecure_http`，并输出醒目警告。配置验证错误不得回显 URL 中的 userinfo、query 或秘密值。

### P1-8：扫描配置字段存在但 CLI 不加载

**证据**：`src/aegisflow/config.py:98` 定义 `AppConfig.scan` 和 `analysis`，但 `src/aegisflow/cli.py:60` 只从 TOML 加载 provider/routing，扫描限制、语言和规则开关保持默认值；未知配置段也可能被忽略。

**影响**：用户以为已限制文件大小、总量、语言或启用规则，实际运行配置不同。赛事复现实验和资源安全声明不可审计。预算参数也未纳入 `configuration_digest`，不同预算可能得到同一配置摘要。

**修改要求**：完整解析并严格校验 `[scan]`、`[analysis]`、`[routing]`、`[provider]`；拒绝未知字段；用单一 `RunConfig` 记录所有实际生效值，包括请求、token 和费用上限。不同有效配置必须产生不同 digest。

### P1-9：参赛量化指标的名称或采样时点错误

**误报率**：`src/aegisflow/benchmark/__init__.py:87` 使用 `FP / (TP + FP)` 并命名为 `false_positive_rate`。该公式实际是 false discovery rate（`1 - precision`）。经典 FPR 是 `FP / (FP + TN)`，当前 ground truth 没有定义 TN，无法计算。

**首个高危发现时间**：`src/aegisflow/cli.py:137` 在整个 workflow 完成后才调用 `perf_counter()` 填写每个高危 finding 的发现时间，因此该值接近总扫描耗时，而不是首个高危被发现的时刻。

**修改要求**：

- 将现有字段重命名为 `false_discovery_rate`，或定义独立负样本/扫描单元并正确计算 TN 与 FPR。
- 在候选产生或 finding 决策当刻记录 monotonic 时间戳。
- 迁移 JSON schema、文档与测试，明确每个指标的分母、样本单元和空集合处理。

### P1-10：函数参数一律视为外部 source，可能产生高置信误报

**证据**：Python `src/aegisflow/analyzers/python.py:60` 和 JavaScript `src/aegisflow/analyzers/javascript.py:86` 将所有函数参数直接标为 source。在没有调用点或框架入口证据时，内部 helper 即使只由常量调用，也可能得到约 `0.97` 的 confirmed finding。

**影响**：提高误报率，并因高置信自动确认进一步绕过 Agent 复核。

**修改要求**：区分“潜在参数 taint”和“已证实外部输入”；未知调用上下文应降为 `likely/needs_review`，或者通过框架入口识别、调用图和跨过程证据确认来源。

### P1-11：报告摘要把已拒绝项计入“最终发现”

**证据**：`src/aegisflow/reporting/__init__.py:411` 按所有 findings 汇总 severity，包括 `disposition=rejected`；HTML 将其显示为最终安全态势。CLI 阈值判断却排除 rejected。

**影响**：同一报告的摘要和退出逻辑语义不一致；评委可能把已排除项误认为最终高危。

**修改要求**：按 disposition 分组展示；最终确认摘要只计入 `confirmed/likely/needs_review`，另列 rejected 及其反证。

### P1-12：文档声明的退出码与实现不一致

**证据**：README 和 `docs/spec.md:214` 声明必需 Agent 失败返回 4，但 provider 异常和预算耗尽在 `src/aegisflow/providers/review.py:98` 被降为 `needs_review`，CLI 没有实现对应 exit 4。报告写入位于主要异常映射之外，权限或 I/O 错误可能成为未处理异常。

**修改要求**：定义清晰的退出矩阵：参数错误 2、不可信/不完整扫描或输出失败 3、严格 Agent 模式失败 4。增加 `--require-agent-success` 或等价策略，并覆盖 provider 超时、无效响应、预算耗尽和写入失败测试。

### P1-13：不可信 provider 用量可削弱本地硬预算

**证据**：`src/aegisflow/providers/review.py:305` 在请求前按本地估算预留预算，但 `src/aegisflow/providers/review.py:351` 会根据 provider 返回的 usage 数据调整或释放预留。provider 响应在本项目威胁模型中并不可信；恶意或不兼容服务可以持续报告零 token 或明显偏低的用量。

**影响**：同一预算额度可能被重复用于后续请求，导致“最大 token/费用”不再是严格的本地硬上限。赛事报告中的成本也可能依赖无法验证的服务端自报数据。

**修改要求**：本地保守估算应作为不可退款的硬预算累计值；provider 自报 usage 只作为独立观测指标保存，不得放宽后续调用额度。增加连续零 usage、缺失 usage、负数/异常 usage 和实际响应超限测试。

### P2-1：上下文截断会破坏 JSON

**证据**：`src/aegisflow/providers/review.py:195` 直接按 UTF-8 字节截断已经序列化的 JSON，再追加一个对象片段。截断可能发生在字符串或结构中间，生成无法解析的消息。本轮在较小 `max_context_bytes` 下已复现 `JSONDecodeError`。

**修改要求**：在节点或字段边界裁剪原始结构，加入 `context_truncated=true` 后重新执行一次 `json.dumps`；对多字节字符和每个边界值做解析测试。

### P2-2：资源限制不能覆盖所有拒绝服务场景

**证据**：`src/aegisflow/ingest/repository.py:165` 对每层执行 `sorted(directory.iterdir())`，会先物化所有条目；`max_files` 只统计支持的源文件。包含海量无关文件的目录仍可消耗大量内存和排序 CPU。provider 在 `src/aegisflow/providers/review.py:327` 对 HTTP 响应没有显式体积上限。扫描大小配置也没有绝对上界。

**修改要求**：增加 `max_entries/max_directories/max_path_bytes`；采用受限枚举策略；限制响应 Content-Length 与实际读取字节；对 TOML、ground truth 和其他控制文件增加读取大小限制；给配置增加系统级硬上限；必要时将解析和 provider 调用放到有 wall-clock、CPU、内存限制的子进程或容器中。

### P2-3：死配置和未完成的路由语义

`src/aegisflow/config.py:53` 定义 `auto_reject_confidence`，但 `route_candidate` 不读取该字段；真实 analyzer 也不会生成 `proven_safe=True` 的候选。该配置当前不可观察、不可验证。

**修改要求**：若不需要则删除并迁移配置；若保留，必须规定安全证据类型、置信门槛和真实入口测试，不能仅凭布尔值无条件排除漏洞。

### P2-4：模型外发脱敏不能称为完整秘密保护

当前正则只覆盖有限的常见形式，对 JWT、GitHub token、非标准 `token:`、Authorization 变体、业务密钥和字符串字面量可能漏脱敏。配置验证异常也可能回显包含秘密的输入。

**修改要求**：将“脱敏”文案改为“尽力过滤”；提供外发前预览、字段允许列表和完全禁止外发模式；引入成熟 secret scanner 或语言级 literal stripping；测试多类 token、JSON key、URL userinfo/query 和错误日志。

### P2-5：工程复现与供应链证据不足

- `pyproject.toml` 只有版本范围，没有锁文件和哈希，比赛环境不能精确复现。
- 未发现 CI 工作流、跨平台矩阵、依赖漏洞检查、SBOM、类型检查和 wheel 安装 smoke test。
- 当前环境的 pytest 为 9.0.2，而项目 dev 约束声明 `<9`；本次通过不等于受支持环境已验证。
- 两个链接安全测试在当前 Windows 环境跳过。

**修改要求**：锁定依赖与哈希；生成 SBOM；加入 Linux/Windows CI、受支持 Python 矩阵、pytest/ruff/type check、构建安装、CLI smoke、依赖审计和链接安全测试。

## 5. 参赛要求差距

### 5.1 Agent 落地成果不足

赛事要求展示 Agent 落地成果与全流程自动化逻辑。当前真实默认输入不会进入模型复核，因此只能证明“存在 Agent 代码”，不能证明“Agent 在产品流程中实际工作”。修复 P1-1 并提供真实请求日志、决策差异、失败降级和成本记录，是参赛前置条件。

### 5.2 量化对照尚不成立

赛事要求对比传统模式的漏洞发现率、误报率、审计量级、单高危发现时长、模型成本和人机验证时间比例。当前缺口包括：

- 没有独立留出集，只有 16 个参与开发的内置回归样例。
- 没有“纯人工”或既有扫描器对照组。
- 误报率公式命名错误，且没有 TN 定义。
- 首个高危发现时间采样错误。
- 只有人工复核数量，没有人工复核耗时和人机时间比例。
- 默认真实扫描的模型请求数为 0，无法证明 Agent 成本或增益。
- benchmark 产物缺少完整 provenance，例如代码版本、样本 digest、平台、配置、预算和 FP/FN 明细。

### 5.3 SRC 定向与靶场能力未验证

项目当前接收本地源码目录，不包含目标发现、授权边界管理、代码获取、SRC 平台适配、靶场输入输出协议或在线闯关控制。`docs/arena-adapter.md` 是检查清单，不是已实现适配器。在没有官方协议和真实试跑日志前，不得宣称支持赛事靶场。

### 5.4 实践案例证据不足

`docs/practice-case.md` 可以作为模板，但模板或模拟样例不能替代授权、脱敏、人工确认的真实实践案例。至少需要一个案例记录授权范围、代码规模、发现证据、人工验证、修复建议、耗时、复现步骤和脱敏说明。

### 5.5 能力范围与赛事方向存在边界

项目符合源码安全审计方向，但不支持二进制分析、动态执行、主动利用、自动修复、跨文件/跨过程完整污点分析和运行时可利用性判断。提交材料必须明确这一边界，不能用“攻防全链路”暗示上述能力已经存在。

### 5.6 提交材料仍需最终化

已有中文 README、技术文档、提交包草案和演示脚本，但仍需补齐：不超过 5,000 字的最终技术方案、团队分工、授权脱敏案例、独立对照实验、真实 Agent 运行证据、五分钟内演示视频或在线 Demo，以及官方靶场验证记录。

## 6. 残余风险（尚未确认成漏洞）

以下问题需要专门测试或结合部署模型评估：

- 仓库根路径检查存在 `lstat` 与 `resolve` 分离，攻击者能并发替换目录时可能有 TOCTOU 风险。
- hard link 不在当前 symlink/reparse 防护范围内；是否构成越界取决于威胁模型和仓库获得方式。
- 用户可配置任意 provider endpoint；只有当配置文件也被视为不可信输入时，才进一步形成 SSRF/内网访问风险。
- Python AST、Tree-sitter、Jinja2、HTTPX 及其依赖自身仍可能存在供应链漏洞或对抗性输入性能问题。
- 未使用进程/容器隔离，极端语法输入可能消耗 CPU 或内存。

本轮没有确认 HTML 报告 XSS：模板使用 `autoescape=True`，现有 hostile-content 测试通过，HTML 也没有脚本或外部资源。这一结论仅适用于当前模板与测试输入。

## 7. 推荐整改顺序

### 第一阶段：修复安全边界和结果可信度

1. 安全输出写入，消除链接逃逸和 TOCTOU。
2. 分析错误/读取错误/配额截断 fail-closed，加入扫描完整性状态。
3. 按污点域拆分 sanitizer，修复跨规则漏报。
4. 修复控制流、路径守卫和分支状态合并。
5. 限制模型 reject 权限并强制反证节点契约。

### 第二阶段：使 Agent 和指标真实可验收

1. 让真实歧义候选进入 Agent 路由并增加 CLI E2E。
2. 修复 FPR/FDR 和首高危时间指标。
3. 完整加载运行配置并记录 digest/provenance。
4. 实现一致的退出码和严格 Agent 模式。
5. 修复结构化上下文截断、HTTPS 和响应大小限制。

### 第三阶段：补齐赛事证据

1. 建立未参与调优的独立留出集。
2. 完成人工/传统工具/offline/agent 四组对照。
3. 提供授权脱敏案例和原始复核记录。
4. 完成官方靶场适配与至少一次可审计试跑。
5. 锁定依赖、建立跨平台 CI、生成 SBOM 和最终演示材料。

## 8. 提交前验收清单

- [ ] 输出路径链接/重解析点不能覆盖仓库外文件。
- [ ] malformed、不可读、超限输入不会得到“完整扫描成功”。
- [ ] 跨漏洞域 sanitizer 回归测试全部通过。
- [ ] `with/match/try/if-else/arrow function/早退` 控制流测试通过。
- [ ] 无有效反证节点的模型 reject 不能隐藏本地高危候选。
- [ ] 公网 endpoint 强制 HTTPS，外发内容可预览并有明确同意。
- [ ] 真实 analyzer 输入能够有依据地触发 Agent 三阶段复核。
- [ ] FDR/FPR、首高危耗时、人机时间比例定义与实现一致。
- [ ] 完整运行配置、预算、代码版本、样本 digest 和平台写入报告。
- [ ] exit 0/1/2/3/4 的实现、文档和测试一致。
- [ ] 独立留出集和传统模式对照实验完成。
- [ ] 授权脱敏实践案例、最终技术方案和演示材料完成。
- [ ] 官方靶场协议确认且完成真实试跑。
- [ ] Linux/Windows CI、锁文件、SBOM、依赖审计和安装 smoke test 完成。

## 9. 最终判断

AegisFlow 的架构方向与赛事主题匹配，并且比单纯调用大模型的演示项目更重视确定性证据、成本和可复现性。但当前最关键的问题不是“再增加更多漏洞规则”，而是先保证：**不会越界写文件、不会把漏扫当成功、不会因错误净化或控制流模型漏掉明显漏洞、不会让无反证的模型输出隐藏本地发现、Agent 路径真实可达、指标定义真实正确。**

完成 P0/P1 整改并取得独立数据、真实 Agent 调用和靶场试跑证据后，项目才适合以“可验证的 Agent+ 源码安全审计系统”参加评审。

## 10. 整改状态（本轮集成基线）

本节仅记录后续整改结果，不改写前述审查发生时的证据和结论。

- 本轮集成基线：`224 passed, 4 skipped`。
- 已完成：FDR 字段迁移、扫描完整性、严格 Agent 退出码、HTTPS/loopback 约束、不可退款本地预算、`rejected` 单列、尽力过滤表述等。
- 4 个 skip 来自当前 Windows 账户缺少符号链接权限；并发 junction 风险仍不能宣称完全消除。
- 独立留出集、授权案例、真实 provider、官方靶场仍未取得外部证据。
