# NP 第二批回归 DEX

源自本项目 fixture v2（固定 220 项），`original` 为构建基线，其余为用户用 NP 管理器生成的样本。原 APK 保留在 tmp；资源内容逐字节等于相应 APK 的 classes.dex。与第一批资源分开冻结，不修改预期来迁就混淆行为。

| 文件 | 来源 APK | DEX SHA-256 |
| --- | --- | --- |
| original | `tmp/fixture-v2/fixture-v2-original.apk` | `78ae4339eedde8eef86a55c00288f8a64c298937565293ab87dd6ff3035e7718` |
| opt | `tmp/fixture-v2-opt.apk` | `a681fd6979af5960dfa050661b9b226bdea32542d7970ea337a371b67cb38860` |
| instruction | `tmp/fixture-v2-instruction.apk` | `bf9c483b76d4ae617160d0db1bdfa0cdf75025811a54dbc7511a6da94cc95ccf` |
| flower | `tmp/fixture-v2-flower.apk` | `e53c94e9af95b60cc30e59dbea58095fd598357ab16c0588e543881b433c3edd` |
| string | `tmp/fixture-v2-string.apk` | `92a07066e361bfe26c21a1ac5a760685de999e71d86ff7c5bde1d0dc1506f849` |
| string-antidecrypt | `tmp/fixture-v2-string-antidecrypt.apk` | `87947bdf17b3b3c59747ae150463017375cfa9523989ab546ff6af454f301721` |

后续第三批使用了同名 `tmp/fixture-v2-opt.apk`；当前该 APK 的 DEX 对应 `../np-batch3/opt.dex`（`9d38c23fc08ee4cd342b358e963564cb9d66696de79ecf8bbef0928c6781cef6`）。本目录 `opt.dex` 保留第二批原始内容，两份 Optimization 样本分别回归，不能仅按源文件名判定相同。

`Batch2IntegrationTest` 读取这些文件，不需要 ADB、Android SDK、JADX 或 Z3。本地设备验证与额外位向量证明保存在 `tmp/batch2-implementation/`，不随仓库发布。
