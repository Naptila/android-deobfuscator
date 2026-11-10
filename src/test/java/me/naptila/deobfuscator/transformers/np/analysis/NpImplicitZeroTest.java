package me.naptila.deobfuscator.transformers.np.analysis;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.io.DexFiles;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static me.naptila.deobfuscator.transformers.np.analysis.NpHelperShapesTest.*;
import static org.junit.Assert.*;

public class NpImplicitZeroTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final ImmutableFieldReference DEPENDENT = new ImmutableFieldReference(OWNER, "dependent", "I");

    private DexFile fixture(List<Field> fields, Method... methods) {
        return new ImmutableDexFile(Opcodes.forApi(28), List.of(new ImmutableClassDef(OWNER, 1,
            "Ljava/lang/Object;", List.of(), null, Set.of(), fields, List.of(methods))));
    }

    private Field zeroField(int extraFlags) {
        return new ImmutableField(OWNER, "flag", "I", PUBLIC_STATIC | extraFlags, null, Set.of(), Set.of());
    }

    @Test public void omittedStaticValueAndExplicitZeroWritesRemainZeroAfterDexReload() throws Exception {
        for (boolean writeZero : new boolean[]{false, true}) {
            var methods = new ArrayList<Method>(List.of(guard(false)));
            if (writeZero) {
                var b = new MethodImplementationBuilder(1);
                constant(b, 0, 0);
                b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, FIELD));
                b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                methods.add(method("write", List.of(), "V", b));
            }
            DexFile input = fixture(List.of(zeroField(0)), methods.toArray(Method[]::new));
            Path path = directory.getRoot().toPath().resolve("zero-" + writeZero + ".dex");
            DexFiles.write(path, input);
            var dex = new DexContext(DexFiles.read(path));
            var analysis = NpAnalysis.of(dex);
            assertEquals(Integer.valueOf(0), analysis.model().fields().get(Signatures.of(FIELD)));
            assertEquals(1, analysis.stableIntegerFields());
            assertEquals(0, analysis.rejectedIntegerFields());
            var call = new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard(false));
            var state = new Constants();
            analysis.model().step(call, state);
            assertEquals(-293, state.result());
        }
    }

    @Test public void zeroGuardPreventsSpuriousRejectionOfDependentFields() throws Exception {
        var b = new MethodImplementationBuilder(2);
        constant(b, 0, 1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 1, DEPENDENT));
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method dependentGuard = method("dependentGuard", List.of(), "I", b);
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard(false)));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LTZ, 0, b.getLabel("stable")));
        constant(b, 0, 11);
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("store")));
        b.addLabel("stable"); constant(b, 0, 7);
        b.addLabel("store");
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, DEPENDENT));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method writer = method("writeDependent", List.of(), "V", b);
        var dependent = new ImmutableField(OWNER, "dependent", "I", PUBLIC_STATIC,
            new ImmutableIntEncodedValue(7), Set.of(), Set.of());
        DexFile input = fixture(List.of(zeroField(0), dependent), guard(false), dependentGuard, writer);
        Path path = directory.getRoot().toPath().resolve("dependent.dex");
        DexFiles.write(path, input);
        var analysis = NpAnalysis.of(new DexContext(DexFiles.read(path)));
        assertEquals(Map.of(Signatures.of(FIELD), 0, Signatures.of(DEPENDENT), 7), analysis.model().fields());
        assertEquals(0, analysis.rejectedIntegerFields());
    }

    @Test public void nonzeroUnknownAndInitializerWritesStillRejectZeroAndVolatileIsExcluded() {
        for (String mode : List.of("nonzero", "unknown", "initializer", "volatile")) {
            var b = new MethodImplementationBuilder(1);
            List<ImmutableMethodParameter> params = List.of();
            if (mode.equals("unknown")) params = List.of(new ImmutableMethodParameter("I", Set.of(), "input"));
            else constant(b, 0, 1);
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, FIELD));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            String name = mode.equals("initializer") ? "<clinit>" : "write";
            Method writer = mode.equals("initializer")
                ? new ImmutableMethod(OWNER, name, params, "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                    Set.of(), Set.of(), b.getMethodImplementation())
                : method(name, params, "V", b);
            var field = zeroField(mode.equals("volatile") ? AccessFlags.VOLATILE.getValue() : 0);
            var analysis = NpAnalysis.of(new DexContext(fixture(List.of(field), guard(false), writer)));
            assertTrue(mode, analysis.model().fields().isEmpty());
            assertEquals(mode, mode.equals("volatile") ? 0 : 1, analysis.rejectedIntegerFields());
        }
    }
}
