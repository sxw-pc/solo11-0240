# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

计量账务链把两家基础设施供应商夜交的纸面计量页核成真实可追的两本账。`physical_usage.py` 是物理用量识别模块：同一物理宿主同一分钟的实耗只计一次，跨门户复抄、宿主别名、虚机迁移都不创造核秒；派生的物理用量与租户归属由原始证据确定性重算，总量须同独立控制器共同校时原件守恒，分歧即整批拒付。租户账单只含所有相容迁移历史中都能证明属于它的用量——迁移条码缺末四位、多页网页标签冲突或匹配不到注册容器时一律挂起，不依网页标签、上传先后或平均分摊定归属；身份未定不免除供应商付款责任。`meter_capture.py` 整页事务化采录，同页重扫只回放；`vendor_payable.py` 由采购签发按真实总耗用结账，控制器证明而纸页未到的耗用照付；`tenant_charge.py` 由客户账务签发只开确证差额。两本账具名签发人不得互相兼任。`billing.dispatch` 封盘支付批次后，晚到凭条只能产生补票、冲回或追索单，旧回单永不修改；`meter.deploy_proof` 用阶段固定成员回执证明部署副本，把扫描原件、共同校时、发行窗、部署副本和支付批次串成一条链，全部命令经 `command_events` 由 `audit` 重放验证。演示：`python -m cloudroll billing fixtures/billing_normal.json --db billing.sqlite`。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。
