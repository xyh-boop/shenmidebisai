# AegisFlow

AegisFlow 是一个以证据为核心、优先本地运行的源代码安全审计 Agent，面向 Python 与 JavaScript/TypeScript 项目。它将确定性候选发现、本地 Source-to-Sink 证据图、成本感知路由与可选的对抗式模型复核结合起来，当前 MVP 覆盖命令注入、SQL 注入、路径遍历和不安全反序列化四类风险。

扫描器将待检仓库视为不可信数据：不会导入、执行、构建、安装或测试目标代码。离线模式为默认模式，无需凭据与网络访问。

## 核心能力

- **本地优先**：Python AST 与 JS/TS Tree-sitter 解析均在本地完成，离线扫描不访问网络。
- **证据可追溯**：每条发现包含来源、传播、约束、净化处理与危险汇点等证据节点。
- **Agent 分层复核**：仅将证据不足但风险较高的候选交由 Verifier、Critic 与 Arbiter 复核，避免无边界调用模型。
- **成本与风险受控**：限制模型请求数、上下文、令牌与预算；无效响应、超时或预算耗尽会标记为 `needs_review`，不会被静默确认为漏洞。
- **结果可复现**：离线结果按稳定顺序输出；基准测试以独立真值清单统计定位级 Precision、Recall 和 F1。
- **双格式报告**：支持规范 JSON 与独立 HTML 报告；HTML 界面为简体中文，JSON 契约、规则 ID 和证据字段保持稳定。

## 快速开始

环境要求：Python 3.11 或更高版本。

```powershell
python -m pip install ".[dev]"
aegisflow doctor
aegisflow rules --format table
aegisflow scan . --mode offline --format html --output .\artifacts\report.html --fail-on none
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

当发现达到 `--fail-on` 指定阈值时，`scan` 返回退出码 `1`；演示或仅查看结果时请使用 `--fail-on none`。报告可输出到扫描目录之外，或扫描目录中被忽略的 `artifacts/`、`.artifacts/` 路径；输出到待扫描源码范围内的其他路径会被拒绝。

## Agent 模式

复制不含密钥的示例配置 `config/model.example.toml`，选择兼容 OpenAI API 的服务端点，并在环境变量中设置 `api_key_env` 指定的密钥。凭据仅保留在环境变量中，不会写入报告。

```powershell
$env:AEGISFLOW_API_KEY = "..."
aegisflow scan . --mode agent --model-config .\config\model.example.toml --max-requests 8 --max-cost-usd 0.50 --output .\artifacts\agent-report.html --fail-on none
```

Agent 模式只会复核高风险且证据存在歧义的候选。离线基准成绩仍是唯一可重复验证的评测依据，模型辅助结论会单独记录，避免不确定性影响基线。

## 命令与退出码

- `aegisflow doctor`：在不访问网络的前提下检查运行环境和解析器可用性。
- `aegisflow rules`：以表格或 JSON 列出当前锁定的四条规则。
- `aegisflow scan`：生成规范 JSON 或自包含 HTML 审计报告。
- `aegisflow benchmark`：扫描基准样本，并按独立真值清单计算指标。

退出码含义如下：`0` 表示扫描完成且未达到阈值；`1` 表示扫描完成但存在达到阈值的发现；`2` 表示参数或配置无效；`3` 表示输入不可信或解析失败；`4` 表示必需的 Agent 模式调用失败。

## 项目边界

AegisFlow 进行受限的、本地的、主要在函数内的数据流追踪。它不宣称覆盖完整跨文件或全程序污点分析、运行时可达性、框架鉴权分析、二进制分析、主动利用或自动修复。基准分数仅说明当前版本随附样本集与记录配置下的结果，不代表通用准确率。

## 文档

- [产品规格](docs/spec.md)：目标、公开契约、验收标准与边界。
- [系统架构](docs/architecture.md)：流水线、组件职责与 Agent 语义。
- [威胁模型](docs/threat-model.md)：输入、数据处理与安全假设。
- [基准测试方法](docs/benchmark.md)：真值清单与评分口径。
- [五分钟演示脚本](docs/demo-script.md)：比赛展示流程。
- [参赛技术方案](docs/submission-package.md)：不超过 5,000 字的技术方案初稿与提交边界。
- [脱敏实践案例](docs/practice-case.md)：明确标注的模拟案例和正式案例补录模板。
- [对照实验协议](docs/experiment-protocol.md)：传统流程、`offline` 与 `agent` 的指标口径。
- [靶场适配清单](docs/arena-adapter.md)：官方协议确认和试跑验收项。
- [评审意见](docs/competition-readiness-review.md)：当前参赛准备度与待补证据。

## 验证

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```
