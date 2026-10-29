# QMT 兼容沙箱

```bash
python -B scripts/offline-paper-demo.py --broker QMT_COMPAT_SANDBOX
```

该入口只重放固定合成回调，复现部分成交、取消、拒绝、重复与乱序回调，以及断线后重启的去重核对。它使用项目中的模拟适配器和持久化逻辑，不导入 `xtquant`，不访问真实账户或 QMT 运行时。

成功结果必须同时保留：

```json
{
  "real_orders": false,
  "real_broker_accessed": false,
  "qmt_runtime_accessed": false,
  "qmt_vendor_certified": false,
  "xtquant_imported": false,
  "live_order_capability_exposed": false,
  "certification_status": "NOT_RUN_REAL_QMT"
}
```

该沙箱不能证明真实券商接口兼容性，也不构成厂商认证或断电持久性认证。完整合成输出见上级目录的 `SAMPLE_OUTPUT.json`。
