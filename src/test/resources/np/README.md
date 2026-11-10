# NP 回归样本

这些 DEX 来自本仓库 `tmp/apk-fixture` 生成的测试 APK，由用户使用 NP 管理器 3.1.54 / 控制流混淆 8.0 处理；不是外部应用。测试不依赖 tmp 目录、baksmali 或 Python。

| 文件 | 配置 | SHA-256 |
| --- | --- | --- |
| `original.dex` | 未混淆基线 | `ee806c94218bbe23f1545e2aa16d6164b420a816c8c332b5524640b0b49e2652` |
| `opt.dex` | Optimization | `0db6f45b76dca355d34e264e51356024055879a8e6253de4d835af730357e30a` |
| `number.dex` | Digital confusion | `aef1ca747f600957e11b489e6a9bef0d0f594233d1a89e1a16bb6eca15b8823c` |
| `strings.dex` | String Encryption | `0cda75e40914320afca9eba73ec812f777cd136d5855b3e191944886d5b6d651` |
| `planar.dex` | Optimization + Planarization | `5a70652ba66717f7b409e87c947726c03322951c1402359e78d8b6087ae05a4d` |

已知范围：numeric int XOR；短数组 UTF-16 XOR；hash/字段混合状态分发。2026-09-23 已在 Pixel 6a / Android 17 验证第一批 APK 和处理结果，详见根 README；新增 planar 清理后也通过 53/53。样本测试不能代表所有 NP 版本和选项。
