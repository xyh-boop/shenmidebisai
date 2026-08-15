# AegisFlow 参赛技术方案

## 1. 项目摘要

AegisFlow 面向 Python 与 JavaScript/TypeScript 源代码安全审计，重点检测命令注入、SQL 注入、路径遍历和不安全反序列化四类问题。系统将仓库当作不可信只读数据，在本地完成安全读取、语法分析、Source-to-Sink 证据图构建和确定性风险路由；只有高风险且证据存在歧义的候选才进入受预算和结构化契约约束的 Verifier、Critic、Arbiter 复核。

系统定位是“以确定性静态分析为主、以受约束模型复核为辅的本地源码安全审计 Agent”，不宣称二进制分析、全程序污点分析、动态利用或自动修复能力。

## 2. 技术架构

```text
安全读取 -> Python AST / Tree-sitter -> 候选与证据图
        -> 置信度与成本路由 -> 本地确认/拒绝或受约束复核
        -> JSON/HTML 报告 -> 独立真值基准评分
```

读取层限制文件类型、数量、大小、深度和路径范围，不跟随符号链接，不执行目标代码。分析层记录 `source`、`propagation`、`sanitizer`、`constraint`、`sink` 节点及其关系。报告层使用稳定指纹、规范化路径和固定排序保证重复运行可比较。

## 3. 核心方法

四条规则均采用本地证据图。完整且高置信度的 Source-to-Sink 路径由离线流程确认；已证明安全的常量、参数化查询或路径约束被抑制；高风险歧义候选才交给模型。外部上下文在发送前裁剪并尽力过滤，不能宣称完整脱敏；模型请求受请求数、上下文、令牌和不可退款本地硬预算限制，provider 自报 usage 只作观测。公网 endpoint 必须使用 HTTPS，明文 HTTP 只允许显式开启的 loopback 调试。无效响应、超时、未知证据引用或预算耗尽统一降级为 `needs_review`。

每次分析返回 `AnalysisResult`，其中 `complete=false` 或任一 `ERROR` 诊断表示扫描覆盖不完整。报告仍可用于审计，但扫描退出码为 `3`。`rejected` 结果单列展示，不进入最终严重性摘要。

## 4. 实践案例与实验

仓库内提供一个明确标注为“脱敏模拟、非真实授权案例”的业务结构样例，展示从请求参数到危险汇点的证据、人工复核记录模板和修复建议。正式提交前必须替换为获得授权的真实案例，或补充授权证明。

内置 16 个固定样例用于回归验证。当前离线结果为 8 个真阳性、0 个假阳性、0 个假阴性，Precision/Recall/F1 均为 1.000，错误发现率 FDR 为 0.000；由于没有 TN 定义，不报告经典 FPR。该结果仅适用于内置样例和记录配置。`docs/experiment-protocol.md` 规定了独立测试集、传统规则流程对照、`offline`/`agent` 分离统计、失败降级和人工计时方法。当前未连接外部模型服务，因此 `agent` 实测数据仍待补录。

## 5. 靶场适配与边界

当前版本提供本地 CLI、JSON/HTML 报告和离线基准接口，但尚未验证官方靶场的输入输出协议、运行环境、网络策略和资源上限。因此提交材料中只能写“本地原型已验证，官方靶场适配待验证”，不能宣称已具备闯关能力。独立留出集、授权案例和真实 provider 运行记录也仍是外部证据缺口。适配检查项见 `docs/arena-adapter.md`。

## 6. 复现方式

```powershell
python -m pip install ".[dev]"
aegisflow doctor
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark-final.json
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

演示按 `docs/demo-script.md` 执行，提交前还需补充固定版本、固定输入、原始日志、人工复核记录和费用计算依据。

## 7. 团队与提交说明

正式提交包应补充不超过 3 人的团队介绍、研发/评测/演示分工、指定环境试跑记录、授权或脱敏证明，以及不超过 5,000 字的最终 PDF/Markdown。本文件可作为技术方案初稿，不能替代尚未取得的外部授权和靶场证据。
