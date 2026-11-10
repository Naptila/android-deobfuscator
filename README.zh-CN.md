# Android Deobfuscator

[English](README.md) | 简体中文

面向 Android APK 和 DEX 的命令行反混淆工具，直接读取、分析和重写 DEX，支持 APK 多 DEX 联合分析。各功能独立选择，清理自动执行，已支持的混淆模式包括 NP 管理器。

## 构建与运行

需要 JDK 17+，使用仓库内的 Gradle Wrapper：

```bash
./gradlew test installDist
build/install/deobfuscator/bin/deobfuscator --list-transformers
build/install/deobfuscator/bin/deobfuscator \
  --input sample.apk --output sample.cleaned.apk --report report.json
```

Windows 使用 `gradlew.bat` 和生成的 `.bat` 启动脚本。输入支持独立 DEX 或 APK；输出和报告必须使用新文件名。APK 内的类按原 DEX 归属写回，资源内容保留，输出 APK 需要重新签名。

`./gradlew distZip` 生成包含命令行启动脚本、依赖、配置示例和文档的分发包。解压后运行 `bin/deobfuscator`，Windows 使用 `bin/deobfuscator.bat`。

## 规则与默认流程

| 规则 | 功能 |
| --- | --- |
| `np.method-hiding` | 恢复已验证的守卫代理、字面量及成员操作 |
| `np.numbers` | 还原已证明的 int 常量和 wide XOR 常量 |
| `np.instructions` | 简化 int/long 算术与位运算展开，规范构造器对象别名；可选恢复 float/double 加减展开 |
| `np.strings` | 识别 short 数组 XOR 解密方法，恢复已知字符串 |
| `strings.decrypt` | 配置 UTF-16 XOR 或 StringFog Base64/字节 XOR/UTF-8 解密模型 |
| `np.opaque-predicates` | 求值已验证的 hash/GuardInt 辅助方法，化简条件 |
| `np.dispatcher` | 恢复控制流平坦化的 switch 分发路径及共享整数状态更新 |
| `np.flower` | 恢复花指令的 XOR/hash 分发器，包括 switch 与比较链 |

表中顺序就是默认功能顺序。每个方法在功能之后自动执行共享清理，迭代至无改动，默认最多 20 轮；跨方法收尾按链接、普通改写、代理删除、字符串表回收的顺序执行。平坦化、花指令和不透明条件仍是各自独立的功能。

清理参数直接配置在所属功能上：`np.strings` 接受 `removeProtectedStringCalls`，`np.method-hiding` 接受 `assumeClosedWorld` 和 `keepMethods`。共享清理仅调度一次，报告仍保留细分步骤。旧配置中的 `np.cleanup`、`np.method-hiding.cleanup`、`dex.constant-switch` 和 `dex.unreachable` 继续可用；显式清理配置优先，不会重复执行。

`np.reflection` 可选恢复 NP 的反射缓存分发器，需要配置 Android/JAR 成员元数据及运行时假设，因此不在默认流程中。花指令与控制流平坦化、反射混淆与方法隐藏是 NP 中互斥的输入选项；默认配置可以同时包含对应识别规则。

辅助函数按方法体识别，不依赖随机名称。已验证样本覆盖 NP 3.1.54 模板、新版共享整数状态更新的平坦化组合模板和部分 D8 转换后的比较链。未知模板保留并记录跳过原因；资源 ID 解密尚未实现。输出可读性不代表混淆前源码已完全恢复。

## 配置

[配置示例](config.example.yml) 可以直接复制修改：

```bash
build/install/deobfuscator/bin/deobfuscator --config config.example.yml
```

YAML 顶层路径相对于配置文件，CLI 路径相对于当前目录；`classpath` 建议使用绝对路径。`--transformers id,id` 替换整个规则列表，`--dry-run` 在内存中执行处理，但不写出 APK/DEX，仍可写报告。空列表 `transformers: []` 禁用所有规则。现有 `--passes`、`--list-passes` 和 `--xor-method` 快捷参数继续可用。

未知参数、重复规则 ID 和错误类型会报错。各选项的默认值，以及浮点恢复、受保护调用删除、完整程序及数组不可变假设的适用条件，见 [参数说明](docs/configuration.zh-CN.md)。

方法处理失败会回退该方法，报告记录回退、未收敛、跳过和收尾决策。退出码 `0` 表示本次流程完成，`1` 表示配置或处理错误，`2` 表示存在回退或达到轮次上限；退出码不表示所有混淆均已消除。

## 维护与扩展

NP 实现按职责分为 `analysis`、`controlflow`、`strings`、`numbers`、`instructions`、`methodhiding`、`reflection` 和 `support`。代理与反射清理归入各自实现，字符串表回收归入 `strings`，共用的末尾清理由内部 `NpCleanup` 承担。分发路径恢复共用 `DispatcherRecovery`，参数类型校验集中在 `TransformerOptions`。

规则统一通过 `TransformerProvider` SPI 注册。新增规则在 transformer 文件内声明嵌套 Provider，添加 SPI 条目和相应测试；CLI 和引擎不依赖具体规则。通用字符串算法通过 `StringDecoder` 扩展。旧的 `ServiceLoader<DexPass>` 注册方式已移除，插件需改为提供 Provider。

包职责、分析缓存、方法事务、收尾阶段和接入示例见 [扩展说明](docs/extending.zh-CN.md)。

## 验证

```bash
./gradlew clean test installDist distZip
```

回归样本位于 `src/test/resources`，覆盖 NP 字符串、数字、指令替换、平坦化、花指令、比较链、方法隐藏、反射和组合混淆。测试检查异常路径、业务副作用、wide 寄存器、字段/数组逃逸、DEX 写出重读、幂等性，以及命令行配置、预览和输入输出保护。

本地分析记录和 APK 留在 `tmp/`，不随源码与分发包发布。
