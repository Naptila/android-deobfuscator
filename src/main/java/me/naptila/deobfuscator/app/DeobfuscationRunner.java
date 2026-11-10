package me.naptila.deobfuscator.app;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.*;
import java.nio.file.Files;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.dex.EngineProgress;
import me.naptila.deobfuscator.io.*;
import me.naptila.deobfuscator.io.ApkArchive;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.io.OutputFiles;
import me.naptila.deobfuscator.report.JsonReport;

/** File-based workflow for command-line execution and programmatic callers. */
public final class DeobfuscationRunner {
    public enum Stage { VALIDATING, READING, TRANSFORMING, WRITING_DEX, WRITING_REPORT, COMPLETE, WRITING_APK }
    private final Deobfuscator deobfuscator;
    public DeobfuscationRunner(Deobfuscator deobfuscator) { this.deobfuscator = deobfuscator; }
    public FileRunResult runInput(RunConfiguration config) throws IOException { return runInput(config, stage -> {}); }
    public FileRunResult runInput(RunConfiguration config, Consumer<Stage> progress) throws IOException {
        return runInput(config, progress, event -> {});
    }
    public FileRunResult runInput(RunConfiguration config, Consumer<Stage> progress, Consumer<EngineProgress> detail) throws IOException {
        if (config.input() == null) throw new IllegalArgumentException("input is required");
        byte[] magic;
        try (var stream = Files.newInputStream(config.input())) { magic = stream.readNBytes(4); }
        if (Arrays.equals(magic, new byte[]{'d', 'e', 'x', '\n'}))
            return new FileRunResult(false, List.of(), Map.of(), List.of(), run(config, progress, detail));
        if (!Arrays.equals(magic, new byte[]{'P', 'K', 3, 4})) throw new IOException("Input must be a DEX or APK file");
        progress.accept(Stage.VALIDATING);
        validate(config);
        Path output = absolute(config.output()), report = absolute(config.report());
        progress.accept(Stage.READING);
        try (ApkArchive apk = new ApkArchive(config.input())) {
            progress.accept(Stage.TRANSFORMING);
            var result = deobfuscator.transform(apk.combined(), config.transformers(), config.maxRounds(), detail);
            var fileResult = new FileRunResult(true, apk.dexNames(), apk.classOwners(), apk.removedSignatures(), result);
            if (!config.dryRun()) {
                progress.accept(Stage.WRITING_APK);
                apk.write(output, result.dex());
            }
            if (report != null) {
                progress.accept(Stage.WRITING_REPORT);
                OutputFiles.writeText(report, JsonReport.write(fileResult, config.dryRun()));
            }
            progress.accept(Stage.COMPLETE);
            return fileResult;
        }
    }
    public DexEngine.Result run(RunConfiguration config) throws IOException {
        return run(config, stage -> {});
    }
    public DexEngine.Result run(RunConfiguration config, Consumer<Stage> progress) throws IOException {
        return run(config, progress, event -> {});
    }
    private DexEngine.Result run(RunConfiguration config, Consumer<Stage> progress, Consumer<EngineProgress> detail) throws IOException {
        progress.accept(Stage.VALIDATING);
        validate(config);
        Path input = absolute(config.input()), output = absolute(config.output()), report = absolute(config.report());
        progress.accept(Stage.READING);
        var dex = DexFiles.read(input);
        progress.accept(Stage.TRANSFORMING);
        DexEngine.Result result = deobfuscator.transform(dex, config.transformers(), config.maxRounds(), detail);
        if (!config.dryRun()) {
            progress.accept(Stage.WRITING_DEX);
            DexFiles.write(output, result.dex());
        }
        if (report != null) {
            progress.accept(Stage.WRITING_REPORT);
            OutputFiles.writeText(report, JsonReport.write(result, config.dryRun()));
        }
        progress.accept(Stage.COMPLETE);
        return result;
    }
    private static void validate(RunConfiguration config) throws IOException {
        if (config.input() == null) throw new IllegalArgumentException("input is required");
        if (!config.dryRun() && config.output() == null)
            throw new IllegalArgumentException("output is required unless dryRun");
        Path input = absolute(config.input()), output = absolute(config.output()), report = absolute(config.report());
        if (!config.dryRun()) OutputFiles.checkNew(output);
        if (report != null) {
            OutputFiles.checkNew(report);
            if (report.equals(input) || report.equals(output)) throw new IllegalArgumentException("Report path must be distinct");
        }
    }
    private static Path absolute(Path path) { return path == null ? null : path.toAbsolutePath().normalize(); }
}
