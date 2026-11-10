package me.naptila.deobfuscator.dex;

import java.util.*;
import me.naptila.deobfuscator.core.Pipeline;
import me.naptila.deobfuscator.core.PassResult;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;

public final class DexEngine {
    public record MethodReport(String method, int edits, boolean converged, boolean rolledBack,
                               List<Pipeline.Step> steps, String error) {
        public MethodReport { steps = List.copyOf(steps); }
    }
    public record DexStep(String pass, PassResult result) {}
    public record Result(DexFile dex, List<MethodReport> methods, List<DexStep> dexSteps, TransformationEvidence.Snapshot evidence) {
        public Result { methods = List.copyOf(methods); dexSteps = List.copyOf(dexSteps); }
        public Result(DexFile dex, List<MethodReport> methods) { this(dex, methods, List.of(), TransformationEvidence.Snapshot.empty()); }
        public Result(DexFile dex, List<MethodReport> methods, List<DexStep> dexSteps) { this(dex, methods, dexSteps, TransformationEvidence.Snapshot.empty()); }
        public long changedMethods() { return methods.stream().filter(m -> m.edits() > 0).count(); }
        public long failedMethods() { return methods.stream().filter(MethodReport::rolledBack).count(); }
        public long dexEdits() { return dexSteps.stream().mapToLong(s -> s.result().edits()).sum(); }
    }
    private final Pipeline<MethodContext> pipeline;
    private final List<DexPass> passes;
    public DexEngine(List<? extends DexPass> passes, int maxRounds) {
        this.passes = List.copyOf(passes);
        pipeline = new Pipeline<>(passes, maxRounds);
    }

    public Result transform(DexFile dex) {
        return transform(dex, progress -> {});
    }
    public Result transform(DexFile dex, java.util.function.Consumer<EngineProgress> progress) {
        DexContext context = new DexContext(dex);
        int total = (int) context.methods().values().stream().filter(m -> m.getImplementation() != null).count();
        // Preparation failures abort the run before output, rather than silently disabling a rule.
        for (DexPass pass : passes) {
            progress.accept(new EngineProgress(EngineProgress.Phase.PREPARING, pass.id(), "", 0, 0, total));
            try { pass.prepare(context); }
            catch (RuntimeException error) {
                throw new IllegalStateException("Preparation failed in " + pass.id() + ": " + error.getMessage(), error);
            }
        }
        List<ClassDef> classes = new ArrayList<>(); List<MethodReport> reports = new ArrayList<>();
        Collection<ClassDef> ordered = context.classes().values();
        for (ClassDef cls : ordered) {
            List<Method> direct = transformMethods(context, cls.getDirectMethods(), reports, progress, total);
            List<Method> virtual = transformMethods(context, cls.getVirtualMethods(), reports, progress, total);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getStaticFields(), cls.getInstanceFields(), direct, virtual));
        }
        DexFile output = new ImmutableDexFile(dex.getOpcodes(), classes);
        List<DexStep> finalSteps = new ArrayList<>();
        List<DexPass> finalizers = passes.stream().filter(p -> p instanceof DexFinalizer)
                .sorted(Comparator.comparing(p -> ((DexFinalizer)p).phase())).toList();
        for (DexPass pass : finalizers) {
            progress.accept(new EngineProgress(EngineProgress.Phase.FINALIZING, pass.id(), "", 0, reports.size(), total));
            DexFinalizer finalizer = (DexFinalizer)pass;
            if (finalizer.requiresCompleteMethods() && reports.stream().anyMatch(r -> r.rolledBack() || !r.converged())) {
                finalSteps.add(new DexStep(pass.id(), PassResult.skipped("DEX finalization retained: incomplete method transactions")));
                continue;
            }
            try {
                var result = finalizer.finish(context, output);
                DexFile candidate = ImmutableDexFile.of(result.dex());
                for (ClassDef cls : candidate.getClasses()) for (Method method : cls.getMethods())
                    if (method.getImplementation() != null) new CodeGraph(method.getImplementation());
                output = candidate;
                finalSteps.add(new DexStep(pass.id(), result.result()));
            } catch (RuntimeException error) {
                throw new IllegalStateException("Finalization failed in " + pass.id() + ": " + error.getMessage(), error);
            }
        }
        return new Result(output, reports, finalSteps, context.evidence().snapshot());
    }
    private List<Method> transformMethods(DexContext dex, Iterable<? extends Method> methods, List<MethodReport> reports,
                                        java.util.function.Consumer<EngineProgress> progress, int total) {
        List<Method> output = new ArrayList<>();
        for (Method method : methods) {
            if (method.getImplementation() == null) { output.add(method); continue; }
            String name = Signatures.of(method);
            progress.accept(new EngineProgress(EngineProgress.Phase.METHODS, "", name, 0, reports.size(), total));
            try {
                MethodContext context = new MethodContext(dex, method);
                Pipeline.Result result = pipeline.run(context, (pass, round) -> progress.accept(
                        new EngineProgress(EngineProgress.Phase.METHODS, pass, name, round, reports.size(), total)));
                Method rewritten = context.finish();
                // Reparse all instruction targets before accepting a method transaction.
                new CodeGraph(rewritten.getImplementation());
                if (result.converged()) dex.evidence().commit(dex, rewritten, context.replacements());
                else dex.evidence().incomplete(context.name());
                output.add(rewritten);
                reports.add(new MethodReport(context.name(), result.edits(), result.converged(), false, result.steps(), null));
            } catch (RuntimeException error) {
                dex.evidence().incomplete(Signatures.of(method));
                output.add(method);
                reports.add(new MethodReport(Signatures.of(method), 0, false, true, List.of(),
                        error.getClass().getSimpleName() + ": " + error.getMessage()));
            }
        }
        return output;
    }
}
