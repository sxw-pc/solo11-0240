# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。来源封签另有 `provenance`、`signature`、`transparency` 三个入口，`python -m cloudroll all` 也可一次重放整条链。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

## 来源封签（provenance）

制品不再只靠“登记摘要等于回执摘要”进入发布。`signature.py` 提供无第三方依赖的 Ed25519 与规范化 JSON（已用 RFC 8032 向量核对），`transparency.py` 提供 RFC 9162 的 Merkle 树头、包含/一致性证明与见证页保存，`provenance.py` 把构建、封签、交叉签名、投放和撤回串成一条来源链。`artifact.py`、`stage.py`、`store.py`、`cli.py` 已接入。

- 字节即身份：登记时从规范化字节重算 SHA-256；同名不同字节是两份制品，不同名同字节合并为一份。名称在一次解析中若指向多个字节流会被判为歧义而不是猜测。
- 构建配方、输入快照和输出文件一并入库，并分别保存配方摘要与快照摘要。重建必须同配方、隔离构建机、独立快照，才允许 `rebuilt_from`。
- 封签语句显式覆盖字节摘要、构建者权限与发行时间；计划一旦引用封签，副本回执必须同时带上 `seal_id` 和真实摘要，旧副本报 D 不会被后登记的 E 改写成已部署 E。
- 透明日志的两张同高度异根树头都原样保存；仅凭到达顺序无法锚定其中一张，必须由已验证的一致性证明把历史接起来。见证人只能签自己的页，不能互相代签，也不能作为离线构建见证。
- 撤销消息迟到时，已投放的封签、回执和客户实际运行的字节都保留，只把封签置为 `contained` 并列出需要停止交付的具体副本。签名页复扫（`signature.rescan`）会把被篡改或失效的页标出，并只影响它真正支撑的封签。

两种事前批准处置：

1. **保留 D**：由与分叉日志无关的离线构建见证核对 D 的字节（`provenance.attest`），再用仍可信的 K2 交叉签名（`provenance.cross_sign`）；尚未投放的计划继续发 D，客户运行原字节。
2. **重建 E**：在隔离构建机按原配方和独立快照重建得到 E，取得 K2 签名并用新日志的一致性证明锚定，另建计划（原计划标记为 `superseded_rebuild`）；曾报过 D 的副本必须先 `provenance.clean` 才能开始 E 的阶段，随后真正装入 E。

若日后证明 D 的构建机已污染，`provenance.quarantine_build(..., machine=True)` 会收回 D 的封签并列出受影响副本；E 是独立构建，不受牵连。

场景 fixture 由 `python3 fixtures/make_provenance.py` 生成：`fixtures/provenance_option_a.json` 与 `fixtures/provenance_option_b.json` 分别完整跑通两种处置，并可用 `python -m cloudroll all fixtures/provenance_option_a.json --db a.sqlite` 重放。密钥为固定测试材料，仅用于离线演示。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、客户端自动迁移、多目标恢复演练。当前版本不实现。
