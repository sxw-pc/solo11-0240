# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。

## 边缘 NAT 来源识别与紧急止损

夜间离线流量页只保存“出口、地址、租户标签、字节数”。共享 NAT、端口复用、采集器钟差和交换机旧连接表会让纸页标签与物理来源不一致，因此本版把四件事分开查实，绝不在报告里直接改一个封锁状态：

1. **物理流（`flow_capture.canonical_flows/locate_flow`）**：纸页只是观测。同页重放返回 `replayed`，新页号重扫按内容摘要去重；同一 `edge + egress_port`（可加五元组）收敛为一条 `physical_flow`，独立计数器 `record_counter` 确认出口真实字节（固定场景两页各 800 实为同一条 800，而不是 1600 两条）。`direction='ingress'` 的页不算外传。
2. **来源历史（`flow_capture.compatible_histories/candidate_sources/tenant_responsibility`）**：沿“真实会话 `record_session` → NAT 映射有效期 `record_nat(valid_from/valid_to)` → 源容器 → 边缘出口”重建。钟差未校时（`record_clock`）时，同一端口上的各租期都相容；交换机 `state='old'/'stale'` 的旧会话只是必须清空的活路径，不单独定责。只有显式核对（`pinning/verified`）或校时后唯一容器的真实会话才能收敛。**实名通知仅在全部相容历史都指向同一租户时放行**，交集为空一律 `withheld`。
3. **交换机动作（`edge_quarantine`）**：`install_rule` 的生效回执与 `clear_sessions` 的旧会话清空回执缺一，`edge_status` 就不是 `contained`；只加规则时状态为 `rule_effective_sessions_pending`，`verify_cut(... )['all_cut']` 为假，旧会话仍 `cleared=0`。回执经 `ingest_receipt/switch_receipt/container_receipt` 幂等入账。
4. **责任通知（`tenant_notice`）**：固定副本 `issue(db, tenant)` 的“按标签汇总、返回字节数、写 `tenant_notices`”契约保留；但裸 `issue` 若发现该租户卷入仍有歧义的物理流，会暂缓并返回 `withheld`（判定对象仍与 800 数值宽松相等）。带 `notice_id` 的 `send_notice/notify` 走幂等通道，超时停驻 `send_unknown`，凭通知网关回执或 `reconcile_notices` 收敛，同键永不发第二封。

### 两种已批准做法（影响范围不同，均切断全部相容历史）

- **做法一：封整个 e1 并清空旧会话**（无需先判明源容器，t1/t2 短暂断网）：
  `edge_quarantine.seal_edge(db, edge='e1', request_id=..., fabric=switch)`，必须收到 `rule_effective` 与 `sessions_cleared` 两张回执后才 `contained`。
- **做法二：p1、p2 都送取证网**（先 `migrate_traffic` 迁走无关流量并收回执，再 `move_to_forensics` + `revoke_egress`，两容器回执齐全才完成；e1 其他客户不受影响）：
  `edge_quarantine.isolate_containers(db, containers=['p1','p2'], fabric=runtime)`。

批准的 `approved_impact` 会被校验：只批准 t1 却封整个 e1 会得到 `impact_outside_approval`。`verify_cut` 对每一种相容来源历史核对“出口已封且旧会话已清”或“该容器已入取证网且外传已撤”。

### 断电、超时与外部幂等回执

`store.open_db` 自动建表/补列；所有写操作在事务内提交，裸 `sqlite3.connect(文件)` 直接调用也会在操作边界提交。本地库断电或通知客户端超时时，外部交换机/编排器/网关保存同一 `request_id` 的幂等回执，重开后调用 `edge_quarantine.reconcile(db, fabric_or_receipts)`（通知用 `tenant_notice.reconcile_notices`）即可重建“实际发生过什么”；回执可先于本地请求存在，会反向重建 `switch_rule/session_clear/container_action/verified_notice`。原 `flow_pages/flow_rows` 永不覆盖，后续结论以 `evidence_correction` 追加纠错。`cloudroll.fabric.ExternalFabric` 是标准库实现的外部幂等系统模拟器（可配置一次通知超时：外部已写回执、调用方收到 timeout）。

### 命令入口与实地执行

新操作均注册进 `cli.COMMANDS`，可用 fixture 经 `apply_command` 重放并由 `audit` 校验，例如：

`python -m cloudroll all fixtures/stop_loss_delivery.json --db incident.sqlite`

其 `audit.verified` 为真。直接对固定 e1:44321 场景执行一种获批处置并保存交换机/容器回执：

`python -m cloudroll.stop_loss edge --db stop_loss.sqlite --receipts deliverables/executed_edge_stop_loss.json`

（另一种做法：`... containers --receipts deliverables/validated_container_play.json`。）交付目录中已保存一次 edge 实地执行的交换机回执（规则生效 + 旧会话清空，`verify_cut.all_cut=true`）与 containers 做法的容器回执；两种执行都把 t1 实名通知暂缓。补入校时与真实会话后，`identify_sources` 才把责任缩到 t1/p1 或 t2/p2，随后方可 `send_notice`。

测试：`python -m unittest discover -s tests -v`。`tests/test_nat_stop_loss.py` 覆盖纸页重扫/冲突、端口复用与钟差、旧会话不定责、实名暂缓与重复通知、超时回执恢复、两种处置的真实影响、旧会话未清空、批准范围越界、断电重开与台账重建、追加纠错、fixture 审计重放和兼容导入面。

