# 维护与扩展

[English](extending.md) | 简体中文

项目只有一个 Gradle 模块。方法变换接口为 `DexPass`，注册和构造统一由同文件内的 `TransformerProvider` 负责；具体算法不进入 CLI。

## 目录职责

| 包 | 职责 |
| --- | --- |
| `core` | 通用 Pass、固定点调度和结果；不依赖 DEX |
| `dex` | 原始输入索引、分析缓存、方法事务、CFG、数据流、指令编辑和通用清理 |
| `transform` | Provider SPI、规则发现、自动安排和去重功能自带的清理、创建独立实例 |
| `config` | YAML、顶层配置、规则参数类型读取 |
| `app` | 内存处理 API 与文件处理流程 |
| `io` / `report` | DEX/APK 读写和 JSON 报告 |
| `cli` | 命令行参数、帮助和退出状态 |
| `strings` | 离线字符串算法及 `StringDecoder` 扩展接口 |
| `transformers.strings` / `transformers.cleanup` | 通用字符串规则和公共清理规则 |

NP 实现在 `transformers.np` 下按职责划分：

| 子包 | 内容 |
| --- | --- |
| 根包 | `NpTransformer` 共享模型准备与资格判断；内部 `NpCleanup` 承担公共末尾清理 |
| `analysis` | `NpAnalysis`、`NpModel`、辅助函数形态、整数表达式、short 表初始化与逃逸分析；初始化形态放在 `NpArrays.Initializer` 中 |
| `controlflow` | 平坦化与花指令识别、比较链、守卫求值；共享 `DispatcherRecovery` 路径恢复 |
| `strings` | 调用处解密、`NpStringCalls` 参数/边界/可删除性证明及 `StringTables` 回收 |
| `numbers` | 常量整数与 wide XOR 还原 |
| `instructions` | int/long 展开、偏移抵消和可选浮点恢复 |
| `methodhiding` | 守卫代理、数组获取器、代理内联与定义清理 |
| `reflection` | 缓存映射、类型证明、成员调用生成、字符串身份与字段分析 |
| `support` | 访问与初始化校验、代理指令重编码 |

NP 各规则共用原始输入的 `NpAnalysis`，外部通过只读视图读取事实。辅助函数可在有界临时方法中规范化后重新验证形态；临时改写不提交输出或清理证据。数组获取器识别复用方法隐藏的代理正文证明，含义与字符串表不可变证明分开。

## 运行生命周期

1. `TransformerRegistry` 保留功能顺序，将 Provider 声明的 `cleanup(options)` 合并到末尾，再创建每次运行独立的规则实例。同名清理仅安排一次；旧配置的显式清理优先。
2. `DexContext` 固化原始输入的类、方法、字段及引用索引。
3. 规则的 `prepare(DexContext)` 每份输入执行一次，建立共享或私有事实。
4. 每个方法创建 `MethodContext`，按配置运行规则至无改动或达到轮次上限。
5. 校验指令目标后提交方法；运行时异常回退该方法全部改写。未收敛的方法可输出已完成改写，但不提交成功恢复证据。
6. `DexFinalizer` 按阶段处理输出快照：链接、普通改写、代理删除、字符串表回收。

准备失败使整次运行停止。收尾默认要求全部方法成功且收敛；必须完成的适配方法链接可独立声明，无需因其他方法回退而跳过。收尾失败时不发布输出文件。

`DexContext` 始终描述原始输入，避免方法遍历顺序改变事实，也避免回退后残留缓存。`MethodContext.original()` 是当前方法的原定义，`originalGraph()` 按需缓存该定义的不可变控制流图，供各规则跨轮次复用。`code()` 是事务内代码；改写后需要重新生成 `graph()` 和数据流分析，不跨改写保存当前代码的指令索引。寄存器扩展或替换事务代码不会改变原定义及其控制流图。

各功能的工厂以 `public static final class Provider` 放在所属 transformer 文件内。单调用的小辅助类并回所属实现中的命名方法；共享的路径恢复、访问证明和数据流仍集中复用。反射清理与方法隐藏定义清理各自由所属功能维护。

## 新增规则

在相应功能包内增加 transformer：

```java
package me.naptila.deobfuscator.transformers.example;

import core.me.naptila.deobfuscator.PassResult;
import dex.me.naptila.deobfuscator.DexPass;
import dex.me.naptila.deobfuscator.MethodContext;

public final class ExampleTransformer implements DexPass {
    public String id() { return "example.cleanup"; }
    public PassResult run(MethodContext context) {
        // 识别模式，证明条件，用 Edits / ExceptionEdits 提交改写。
        return PassResult.unchanged();
    }
}
```

在同一个 transformer 类中增加嵌套 Provider，声明允许的参数并创建新实例（以下为类内代码）：

```java
public static final class Provider implements TransformerProvider {
    public String id() { return "example.cleanup"; }
    public String description() { return "Example cleanup rule"; }
    public DexPass create(TransformerOptions options) {
        options.requireOnly();
        return new ExampleTransformer();
    }
}
```

在 `src/main/resources/META-INF/services/me.naptila.deobfuscator.transform.TransformerProvider` 中追加 `me.naptila.deobfuscator.transformers.example.ExampleTransformer$Provider`，在 YAML 中添加 `example.cleanup`，并补上样本及必要反例测试。嵌套 Provider 必须为 public static 并使用公开无参构造器，规则 ID 必须一致。SPI 发现顺序不影响执行顺序；发现插件也不自动启用。

NP 功能的嵌套 Provider 继承 `NpTransformer.Provider`，默认安排常量分支、不可达代码和 NP 残留清理；需要自身收尾或参数传递时覆盖 `cleanup(options)`。内部兼容 Provider 使用 `internal()` 隐藏普通功能列表中的显式清理入口，旧 YAML 仍可引用这些 ID。单独使用 `new DexEngine(...)` 的底层调用只运行传入的 pass；需要完整功能及自动清理时使用 `Deobfuscator` / `TransformerRegistry`。

参数校验使用 `requireOnly(...)`、`bool(key)` 和 `strings(key)`。布尔读取方法缺省 false，字符串列表缺省空；Provider 负责精确签名等领域校验，也可显式定义不同的默认值。新增已成熟默认规则时再更新 `RunConfiguration.defaults()` 与配置示例。

外部 JAR 使用同一个 Provider SPI。原 `META-INF/services/me.naptila.deobfuscator.dex.DexPass` 入口已移除，旧插件需要包装为 Provider。通用字符串算法可以实现 `StringDecoder`，通过构造 `StringDecryptTransformer` 或其 `StringDecoder` SPI 接入；只有受支持签名和全部已知参数才返回明文。

## 改写约束

- 从输入静态提取常量，不执行目标 APK 的辅助函数。证明返回值已知，与证明原调用可删除是两个条件。
- 方法隐藏通过最多八轮局部固定点识别多层整数守卫包装，仅消费已经验证的代理正文；拒绝未知业务调用、写入、类型转换和未验证读取。包装的正常返回值只用于路径选择，原调用保留，不向共享模型添加可删除事实。多参数代理的简化正文仍有长度上限，并逐条检查寄存器和调用编码。
- 删除或覆盖寄存器值前检查正常与异常后继的活跃性。wide 值占两个 word，任一半被覆盖会使旧值失效。
- 删除已知字符串的无用 hash 调用时，初始化证明取各入口路径的交集；只有静态成员操作正常完成后才增加事实，异常边传播操作前的状态。不要由循环回边、`const-class` 或调用方的初始化依赖推断首次入口已初始化。
- 方法隐藏和 hash 清理共用 `ProxyAccess.initializedBefore` 的路径证明；按各自需要的类过滤事实，计算未完成时保留调用。代理展开必须保留能够建立初始化事实的首次操作。
- 移动可抛异常指令时，有序 handler 列表必须一致。使用 `ExceptionEdits` 重定位 try 范围；保留 catch、finally、业务副作用及调用顺序。
- 分发器特化保留经过路径的必要前缀，拒绝未知状态和循环。比较链与 switch 共用恢复引擎；识别条件留在各自的规则中。
- `Edits` 和 `BranchRelaxation` 负责指令生成与长分支放宽。新增 scratch 可使用 `appendScratchRegisters`，调用方仍需检查指令的 4/8 位寄存器编码限制。
- `TransformationEvidence` 仅提交成功方法事务的恢复记录。代理删除校验原始指纹、最终引用、外部入口和完整输入条件，不按名字或已经简化后的形态猜测来源。
- 解密、无用调用删除和 short 表回收分别由字符串规则、方法级清理和 DEX 收尾负责，复用同一参数与数组证明。
- int/long 简化按模 32/64 位语义验证；float/double 的代数恢复独立且默认关闭，不标记为逐位等价。

用户可选假设及边界见 [参数说明](configuration.zh-CN.md)。不要在新功能中绕过其他规则的回滚、身份或异常检查。

## 验证

```bash
./gradlew clean test installDist distZip
```

优先验证实际样本、未知/越界/逃逸/异常等反例、DEX 写出重读和再次执行零改动。重构应比较相同配置下的输出 DEX 与关键报告，避免仅靠可读性判断成功。

Java 反编译结果适合检查残留，但可能丢失影响浮点舍入的括号，行为验证以 DEX 执行顺序为准。

冻结的回归 DEX 与说明保存在 `src/test/resources`。本地试验 APK、分析脚本、设备日志和临时输出保留在忽略的 `tmp/`，不加入源码提交或分发包。
