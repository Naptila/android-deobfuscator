package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.*;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.app.DeobfuscationRunner;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.config.YamlConfiguration;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.immutable.ImmutableDexFile;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

/** Command-line configuration and file-workflow regressions. */
public class CliWorkflowTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();

    @Test public void configurationRoundTripPreservesPathsOrderAndOptions() throws Exception {
        Path input = directory.getRoot().toPath().resolve("输入 ' #.dex");
        var specs = List.of(new TransformerSpec("strings.decrypt",
                        new TransformerOptions(Map.of("xorMethods", List.of("Lx;->a(I)V")))),
                new TransformerSpec("np.cleanup", new TransformerOptions(Map.of(
                        "assumeClosedWorld", false, "removeProtectedStringCalls", true))));
        var config = new RunConfiguration(input, null, input.resolveSibling("报告.json"), true, 37, specs);
        Path yaml = directory.getRoot().toPath().resolve("configuration.yml");
        Files.writeString(yaml, YamlConfiguration.write(config));
        assertEquals(config, YamlConfiguration.read(yaml));
        var empty = new RunConfiguration(null, null, null, false, 1, List.of());
        Files.writeString(yaml, YamlConfiguration.write(empty));
        assertEquals(empty, YamlConfiguration.read(yaml));
    }

    @Test public void runnerReportsStagesForWritesPreviewAndFailure() throws Exception {
        Path root = directory.getRoot().toPath(), input = root.resolve("input.dex");
        DexFiles.write(input, new ImmutableDexFile(Opcodes.forApi(28), List.of()));
        var runner = new DeobfuscationRunner(new Deobfuscator(TransformerRegistry.discover()));
        var stages = new ArrayList<DeobfuscationRunner.Stage>();
        var config = new RunConfiguration(input, root.resolve("output.dex"), root.resolve("report.json"), false, 1, List.of());
        runner.run(config, stages::add);
        assertEquals(List.of(DeobfuscationRunner.Stage.VALIDATING, DeobfuscationRunner.Stage.READING,
                DeobfuscationRunner.Stage.TRANSFORMING, DeobfuscationRunner.Stage.WRITING_DEX,
                DeobfuscationRunner.Stage.WRITING_REPORT, DeobfuscationRunner.Stage.COMPLETE), stages);
        byte[] previous = Files.readAllBytes(config.output());
        stages.clear();
        assertThrows(java.io.IOException.class, () -> runner.run(config, stages::add));
        assertEquals(List.of(DeobfuscationRunner.Stage.VALIDATING), stages);
        assertArrayEquals(previous, Files.readAllBytes(config.output()));
        stages.clear();
        Path unwritten = root.resolve("preview.dex");
        runner.run(new RunConfiguration(input, unwritten, null, true, 1, List.of()), stages::add);
        assertFalse(Files.exists(unwritten));
        assertEquals(List.of(DeobfuscationRunner.Stage.VALIDATING, DeobfuscationRunner.Stage.READING,
                DeobfuscationRunner.Stage.TRANSFORMING, DeobfuscationRunner.Stage.COMPLETE), stages);
    }
}
