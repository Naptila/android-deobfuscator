package me.naptila.deobfuscator;

import java.nio.file.Path;
import java.util.*;
import java.util.function.UnaryOperator;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import static org.junit.Assert.*;

public class NpStringCleanupTest {
    private static final String OWNER = "Ldev/deobfuscator/fixture/cases/StringCases;";
    private DexFile input;
    private MethodReference decoder;
    @Before public void load() throws Exception {
        input = DexFiles.read(Path.of(getClass().getResource("/np-v2/string.dex").toURI()));
        Method method = new DexContext(input).findMethod(OWNER + "->encryptedLiteral()Ljava/lang/String;").orElseThrow();
        for (Instruction i : method.getImplementation().getInstructions())
            if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m
                    && m.getParameterTypes().equals(List.of("[S", "I", "I", "I"))) { decoder = m; break; }
        assertNotNull(decoder);
    }
    private Method probe(String mode) {
        return probe(mode, mode.equals("protected"));
    }
    private Method probe(String mode, boolean protectedCall) {
        var b = new MethodImplementationBuilder(6);
        if (mode.equals("null")) Fixtures.integer(b, 0, 0);
        else b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference(OWNER, "short", "[S")));
        if (mode.equals("unknown")) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 5));
        else Fixtures.integer(b, 1, mode.equals("negative-start") ? -1 : mode.equals("overflow") ? Integer.MAX_VALUE : 0);
        Fixtures.integer(b, 2, mode.equals("negative-count") ? -1 : mode.equals("overflow") ? Integer.MAX_VALUE : 1);
        Fixtures.integer(b, 3, 73);
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 0, 1, 2, 3, 0, decoder));
        b.addLabel("end");
        if (mode.equals("live") || mode.equals("dead-result")) b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 4));
        if (!mode.equals("live")) Fixtures.string(b, 4, "done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 4));
        if (protectedCall) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 4));
            Fixtures.string(b, 4, "caught"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 4));
            b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        return new ImmutableMethod(OWNER, "probe", List.of(new ImmutableMethodParameter("I", Set.of(), "offset")),
                "Ljava/lang/String;", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    private DexFile map(DexFile source, UnaryOperator<Method> mapper, Method extra) {
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : source.getClasses()) {
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(m -> methods.add(mapper.apply(m)));
            if (extra != null && extra.getDefiningClass().equals(cls.getType())) methods.add(extra);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        return new ImmutableDexFile(source.getOpcodes(), classes);
    }
    private Method clean(DexFile source, Method method) {
        return clean(source, method, false);
    }
    private Method clean(DexFile source, Method method, boolean protectedCalls) {
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(map(source, UnaryOperator.identity(), method),
                List.of(new TransformerSpec("np.cleanup", new TransformerOptions(Map.of("removeProtectedStringCalls", protectedCalls)))), 20);
        assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return new DexContext(result.dex()).findMethod(Signatures.of(method)).orElseThrow();
    }
    private long count(Method method, Opcode opcode) {
        long result = 0; for (Instruction i : method.getImplementation().getInstructions()) if (i.getOpcode() == opcode) result++; return result;
    }
    @Test public void removesUnusedCallDeadObjectResultAndLocalTableRead() {
        for (String mode : List.of("unused", "dead-result")) {
            Method output = clean(input, probe(mode));
            assertEquals(mode, 0, count(output, Opcode.INVOKE_STATIC));
            assertEquals(mode, 0, count(output, Opcode.MOVE_RESULT_OBJECT));
            assertEquals(mode, 0, count(output, Opcode.SGET_OBJECT));
            assertEquals(mode, 1, count(output, Opcode.CONST_STRING));
        }
    }
    @Test public void retainsLiveObjectResultAndProtectedCall() {
        for (String mode : List.of("live", "protected")) {
            Method output = clean(input, probe(mode));
            assertEquals(mode, 1, count(output, Opcode.INVOKE_STATIC));
            if (mode.equals("live")) assertEquals(1, count(output, Opcode.MOVE_RESULT_OBJECT));
            else assertEquals(1, output.getImplementation().getTryBlocks().size());
        }
    }
    @Test public void optInRemovesOnlyProvenUnusedProtectedStringCalls() {
        for (String mode : List.of("unused", "dead-result")) {
            Method method = probe(mode, true);
            assertEquals(1, count(clean(input, method), Opcode.INVOKE_STATIC));
            Method output = clean(input, method, true);
            assertEquals(0, count(output, Opcode.INVOKE_STATIC));
            assertTrue(output.getImplementation().getTryBlocks().isEmpty());
        }
        for (String mode : List.of("live", "unknown", "null", "negative-start", "negative-count", "overflow"))
            assertEquals(mode, 1, count(clean(input, probe(mode, true), true), Opcode.INVOKE_STATIC));
    }
    @Test public void retainsUnknownNullAndInvalidSlicesEvenWithUnusedResults() {
        for (String mode : List.of("unknown", "null", "negative-start", "negative-count", "overflow"))
            assertEquals(mode, 1, count(clean(input, probe(mode)), Opcode.INVOKE_STATIC));
    }
    @Test public void acceptsEmptyInitializersAndRetainsBusinessInitializersOrUnverifiedBodies() {
        var b = new MethodImplementationBuilder(0); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method init = new ImmutableMethod(decoder.getDefiningClass(), "<clinit>", List.of(), "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        assertEquals(0, count(clean(map(input, UnaryOperator.identity(), init), probe("unused")), Opcode.INVOKE_STATIC));
        assertEquals(0, count(clean(map(input, UnaryOperator.identity(), init), probe("unused", true), true), Opcode.INVOKE_STATIC));
        b = new MethodImplementationBuilder(0);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "initialize", List.of(), "V")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        init = new ImmutableMethod(decoder.getDefiningClass(), "<clinit>", List.of(), "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        assertEquals(1, count(clean(map(input, UnaryOperator.identity(), init), probe("unused")), Opcode.INVOKE_STATIC));
        assertEquals(1, count(clean(map(input, UnaryOperator.identity(), init), probe("unused", true), true), Opcode.INVOKE_STATIC));
        DexFile changed = map(input, m -> {
            if (!Signatures.of(m).equals(Signatures.of(decoder))) return m;
            MethodContext context = new MethodContext(m);
            context.code().replaceInstruction(5, new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 2, 6));
            return context.finish();
        }, null);
        assertEquals(1, count(clean(changed, probe("unused")), Opcode.INVOKE_STATIC));
        assertEquals(1, count(clean(changed, probe("unused", true), true), Opcode.INVOKE_STATIC));
    }
    @Test public void retainsCallWhenTableEscapes() {
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference(OWNER, "short", "[S")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method leak = new ImmutableMethod(OWNER, "escapeTable", List.of(), "[S", AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        assertEquals(1, count(clean(map(input, UnaryOperator.identity(), leak), probe("unused")), Opcode.INVOKE_STATIC));
    }
    @Test public void retainsCallWhenHelperAccessIsNotProven() {
        DexFile changed = map(input, m -> {
            if (!Signatures.of(m).equals(Signatures.of(decoder))) return m;
            return new ImmutableMethod(m.getDefiningClass(), m.getName(), m.getParameters(), m.getReturnType(),
                    (m.getAccessFlags() & ~AccessFlags.PUBLIC.getValue()) | AccessFlags.PRIVATE.getValue(),
                    m.getAnnotations(), m.getHiddenApiRestrictions(), m.getImplementation());
        }, null);
        assertEquals(1, count(clean(changed, probe("unused")), Opcode.INVOKE_STATIC));
        assertEquals(1, count(clean(changed, probe("unused", true), true), Opcode.INVOKE_STATIC));
    }
}
