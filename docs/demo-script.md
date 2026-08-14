# 五分钟演示脚本

## 0:00-0:40：安全性与环境

运行 `aegisflow doctor`。说明仓库会被当作不可信的只读数据解析：离线模式下不会导入、执行、构建、安装或测试目标代码，不执行钩子，也不访问网络。

## 0:40-1:10：规则深度

运行 `aegisflow rules --format table`。展示四类刻意收敛但影响较高的漏洞，并说明项目优先提供 Source-to-Sink 证据和抑制条件，而非堆叠大量浅层规则。

## 1:10-2:20：离线扫描

```powershell
aegisflow scan .\benchmarks\fixtures --mode offline --format html --output .\artifacts\report.html --fail-on none
```

打开报告。选择一条命令注入发现，说明其来源、传播、危险汇点、置信度、稳定指纹、修复建议，以及确定性的 Scout/Tracer 决策。随后展示一条未被报出的安全参数化 SQL 或 `basename` 样例。

## 2:20-3:20：可复现指标

```powershell
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

展示 Precision、Recall、F1、假阳性率、扫描行数、耗时和首个高危发现时间。解释独立真值清单与成对安全近似文件，并明确该分数仅适用于当前版本化样本集。

## 3:20-4:20：Agent 工作流与成本控制

展示 `config/model.example.toml`。解释路由：本地证据完整时会离线确认；证据明确安全时会拒绝；只有高风险且存在歧义的候选才会进入 Verifier、Critic 和 Arbiter 复核。说明请求数、令牌、上下文和美元预算均为硬限制。未经明确批准且没有可用凭据时，不要启用真实服务提供方。

## 4:20-5:00：可重复性与范围

再次运行离线扫描并比较规范化发现 ID。最后明确边界：系统只做 Python 和 JS/TS 的本地受限污点追踪，不是全程序分析、运行时可达性分析、二进制分析、主动利用工具或自动源码修改工具。
