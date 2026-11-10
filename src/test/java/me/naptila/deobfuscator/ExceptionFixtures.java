package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.writer.pool.DexPool;

/** Small DEX fixtures with explicit exception paths, also exported for ART execution. */
public final class ExceptionFixtures {
    public static final String OWNER = "Lsample/ExceptionRegression;";
    static final String PROBE = "Ldev/deobfuscator/test/ExceptionProbe;";
    private final MethodReference hash;
    private ExceptionFixtures(MethodReference hash) { this.hash = hash; }
    public static DexFile input() throws Exception {
        DexFile base = DexFileFactory.loadDexFile(Path.of(Objects.requireNonNull(ExceptionFixtures.class.getResource("/np/opt.dex")).toURI()).toFile(), null);
        MethodReference hash = new DexContext(base).methods().values().stream()
                .filter(m -> m.getParameterTypes().equals(List.of("Ljava/lang/Object;")) && m.getReturnType().equals("I"))
                .findFirst().orElseThrow();
        ExceptionFixtures f = new ExceptionFixtures(hash);
        List<ClassDef> classes = new ArrayList<>(base.getClasses());
        classes.add(new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(),
                List.of(f.destinationOnThrow(), f.wideOnThrow(), f.orderedCatch(), f.nestedFinally(), f.deadTry(),
                        f.sharedCall(true), f.sharedCall(false), f.protectedNullHash())));
        return new ImmutableDexFile(base.getOpcodes(), classes);
    }
    static DexEngine.Result transform(DexFile input) {
        return new Deobfuscator(TransformerRegistry.discover()).transform(input, RunConfiguration.defaults().transformers(), 20);
    }
    private static Method method(String name, String ret, MethodImplementationBuilder b) {
        return new ImmutableMethod(OWNER, name, List.of(new ImmutableMethodParameter("I", Set.of(), "input")), ret,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    private void marker(MethodImplementationBuilder b, int register) {
        Fixtures.string(b, register, "exception fixture"); hash(b, register);
    }
    private void hash(MethodImplementationBuilder b, int register) {
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, register, 0, 0, 0, 0, hash));
    }
    private static void invoke(MethodImplementationBuilder b, String name, int register, String ret) {
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, register, 0, 0, 0, 0,
                new ImmutableMethodReference(PROBE, name, List.of("I"), ret)));
    }
    private static void mark(MethodImplementationBuilder b, int value) {
        Fixtures.integer(b, 2, value); invoke(b, "mark", 2, "V");
    }
    private static void ret(MethodImplementationBuilder b, int register) {
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, register));
    }
    private static void caught(MethodImplementationBuilder b, String name, int value) {
        b.addLabel(name); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        Fixtures.integer(b, 0, value); Fixtures.go(b, "done");
    }
    private Method destinationOnThrow() {
        var b = new MethodImplementationBuilder(4); marker(b, 2);
        Fixtures.integer(b, 0, 42); b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 3)); b.addLabel("end"); ret(b, 0);
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1)); ret(b, 0);
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        return method("destinationOnThrow", "I", b);
    }
    private Method wideOnThrow() {
        var b = new MethodImplementationBuilder(6); marker(b, 4);
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Long.MIN_VALUE + 7));
        Fixtures.integer(b, 2, 37); b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 2, 2, 5)); b.addLabel("end");
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 0, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        return method("wideOnThrow", "J", b);
    }
    private Method orderedCatch() {
        var b = new MethodImplementationBuilder(4); marker(b, 2);
        b.addLabel("start"); invoke(b, "raise", 3, "I");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addLabel("end"); Fixtures.go(b, "done");
        caught(b, "arithmetic", 11); caught(b, "runtime", 22); caught(b, "all", 33);
        b.addLabel("done"); mark(b, 9); ret(b, 0);
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("arithmetic"));
        b.addCatch("Ljava/lang/RuntimeException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("runtime"));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("all"));
        return method("orderedCatch", "I", b);
    }
    private Method nestedFinally() {
        var b = new MethodImplementationBuilder(4); marker(b, 2);
        b.addLabel("outer"); b.addLabel("inner"); invoke(b, "raise", 3, "I");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addLabel("innerEnd"); Fixtures.go(b, "done");
        b.addLabel("arithmetic"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        Fixtures.integer(b, 0, 101); mark(b, 1); Fixtures.go(b, "done"); b.addLabel("outerEnd");
        b.addLabel("all"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        mark(b, 9); b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        b.addLabel("done"); mark(b, 9); ret(b, 0);
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("inner"), b.getLabel("innerEnd"), b.getLabel("arithmetic"));
        b.addCatch(b.getLabel("outer"), b.getLabel("outerEnd"), b.getLabel("all"));
        return method("nestedFinally", "I", b);
    }
    private Method deadTry() {
        var b = new MethodImplementationBuilder(4); marker(b, 2); Fixtures.go(b, "done");
        b.addLabel("start"); invoke(b, "raise", 3, "I"); b.addLabel("end"); Fixtures.go(b, "done");
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        Fixtures.integer(b, 0, -1); ret(b, 0);
        b.addLabel("done"); Fixtures.integer(b, 0, 8); ret(b, 0);
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        return method("deadTry", "I", b);
    }
    private Method sharedCall(boolean sameRegion) {
        var b = new MethodImplementationBuilder(4);
        if (sameRegion) b.addLabel("start");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 3, b.getLabel("negative")));
        Fixtures.string(b, 0, "yes"); Fixtures.go(b, "hash");
        b.addLabel("negative"); Fixtures.string(b, 0, "no"); Fixtures.go(b, "hash");
        if (!sameRegion) b.addLabel("start");
        b.addLabel("hash"); hash(b, 0); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        b.addLabel("dispatch"); b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 1, b.getLabel("payload")));
        Fixtures.go(b, "dispatch"); b.addLabel("end");
        b.addLabel("yes"); Fixtures.integer(b, 0, 1); ret(b, 0);
        b.addLabel("no"); Fixtures.integer(b, 0, 2); ret(b, 0);
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1)); Fixtures.integer(b, 0, -1); ret(b, 0);
        b.addLabel("payload"); b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement("no".hashCode(), b.getLabel("no")),
                new SwitchLabelElement("yes".hashCode(), b.getLabel("yes")))));
        b.addCatch("Ljava/lang/RuntimeException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        return method(sameRegion ? "sharedSame" : "sharedCross", "I", b);
    }
    private Method protectedNullHash() {
        var b = new MethodImplementationBuilder(4);
        Fixtures.integer(b, 0, 0); b.addLabel("start"); hash(b, 0); b.addLabel("end");
        Fixtures.integer(b, 0, 0); ret(b, 0);
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1)); Fixtures.integer(b, 0, 77); ret(b, 0);
        b.addCatch("Ljava/lang/NullPointerException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        return method("protectedNullHash", "I", b);
    }
    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0]); Files.createDirectories(out);
        DexFile input = input(); var result = transform(input);
        if (result.failedMethods() != 0 || result.methods().stream().anyMatch(m -> !m.converged())) throw new AssertionError(result.methods());
        DexPool.writeTo(out.resolve("input.dex").toString(), input);
        DexPool.writeTo(out.resolve("cleaned.dex").toString(), result.dex());
        System.out.println("Exception regression DEX exported to " + out);
    }
}
