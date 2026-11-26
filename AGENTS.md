# 项目级 Agent 约束（RiskEngine）

## 默认输出语言：简体中文（强制生效）

1. **会话回复一律使用简体中文**：
   - 无论当前激活的 `SKILL.md`、工作流模板、RFC 文档、代码注释或用户输入提示词使用何种语言（包括纯英文模板或英文提示词），最终在会话中面向用户输出的所有内容——包括战报、进度汇报、分析说明、提问澄清、阻塞报告、代码复核结论与计划摘要——**默认且必须使用简体中文**。
   - 仅当用户在当前轮次**明确要求**使用其他语言（例如“请用英文回复” / “reply in English”）时，才在该次回复中切换语言；后续轮次仍恢复默认简体中文。

2. **技术标识符与专有名词保持原样**：
   - 代码符号、类名、方法名、文件路径、命令行、日志原文、配置键名、状态标识（如 `DONE` / `BLOCKED` / `IN_PROGRESS`）及常见工程术语（如 `JNI`、`AAR`、`ELF`、`ThinLTO`、`git commit`）保持英文原样，不做生硬直译。
   - 仅在明确修改英文文档（如 `README.md`、`docs/Implementation_Details.md`）或遵循仓库约定编写代码注释、提交信息时，按对应文件或仓库原有语言规范编写，不影响会话中面向用户的中文输出。

3. **Artifact 与报告文档**：
   - 生成面向用户阅读的 Markdown 报告、计划或排障总结时，默认使用简体中文编写。

## Agent skills

### Issue tracker

Issues and specs are tracked as local markdown files under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`GLOSSARY.md` + `docs/adr/` at the repo root, created lazily). See `docs/agents/domain.md`.
