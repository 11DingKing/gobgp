# project-03 交付复盘记录

## Prompt 分解

P1：AddVrf 仅在 VRF、route-target 派生路由、label 占用和 Zebra 发布均完成后报告成功并可被查询。
P2：创建期间 label 申请或 Zebra 发布失败会撤销本次 VRF 和已传播路由，并归还已占用 label 以供后续创建使用。
P3：同一创建请求重试不会重复传播 RTC 或 VPN 路由，也不会为同一 VRF 泄漏或分配多个 label。
P4：DeleteVrf 在邻居占用检查或 RIB 删除失败时保留仍被该 VRF 使用的 label 与 Zebra 状态。
P5：删除成功会撤回派生路由和外部 label 后再释放本地位图，任一步失败都返回可重试且不会把已用 label 分给其他 VRF。
P6：并发同名创建删除及迟到 label-chunk 响应按 VRF 实例隔离，不会修改已删除或替换实例。
P7：API 查询、VPN/RTC watcher 与 Zebra 对成功或回滚后的 VRF、路由和 label 观察一致。
P8：未配置 label range 的 VRF、普通成功创建删除和邻居仍占用时的既有拒绝行为保持兼容。

## Prompt-Rubric 对齐表

P1 -> R1：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P2 -> R2：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P3 -> R3：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P4 -> R4：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P5 -> R5：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P6 -> R6：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P7 -> R7：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P8 -> R8：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。

双向覆盖结论：P1-P8 均有对应 Rubric，R1-R8 均可回指 Prompt 明示需求。无额外验收要求。

## 生产路径与生命周期审计

生产入口是 AddVrf/DeleteVrf RPC；状态 owner 是 tableManager VRF/RIB、label bitmap、watcher 与 Zebra client。API 边界是 gRPC 和 ZAPI socket。创建顺序为建 VRF、派生路由、分配 label、ZAPI 发布；删除相反。清理边界覆盖 RIB、watcher、bitmap 和外部 label。可控交错：删除已撤出本地 VRF 后让 Zebra label 发送失败，查询已无 VRF，Zebra 仍持有 label，bitmap 又在只入队后被释放。

## Rubric 结果

```text
1 未通过 ZAPI sendOrError 只把消息放入 outgoing 通道就报告成功，AddVrf 不等待序列化、socket 写入或 Zebra 确认
2 未通过 创建失败回滚依赖只保证入队的 ZAPI 撤销，API 返回时 Zebra 外部状态未确认撤销
3 通过
4 通过
5 未通过 DeleteVrf 先删除 VRF 并传播撤回，随后 label 发送失败会留下已改变查询和 watcher 但 Zebra 仍保留 label 的状态
6 通过
7 未通过 DeleteVrf 的本地查询和 watcher 在 Zebra label 撤回成功前已更新，失败返回后三个观察面不一致
8 通过
```
