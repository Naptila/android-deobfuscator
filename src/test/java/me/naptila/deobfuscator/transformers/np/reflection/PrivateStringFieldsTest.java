package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.Signatures;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class PrivateStringFieldsTest {
    static final String OWNER = "LExample;", STR = "Ljava/lang/String;";
    final ImmutableFieldReference field = new ImmutableFieldReference(OWNER, "status", STR);
    Method make(String name, List<String> params, String ret, int flags, MethodImplementationBuilder b) {
        return new ImmutableMethod(OWNER, name, params.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(), ret, flags, Set.of(), Set.of(), b == null ? null : b.getMethodImplementation());
    }
    DexContext dex(int flags, List<Method> methods, Set<Annotation> annotations) {
        Field f = new ImmutableField(OWNER, "status", STR, flags | AccessFlags.VOLATILE.getValue(), null, Set.of(), Set.of());
        return new DexContext(new ImmutableDexFile(Opcodes.getDefault(), List.of(new ImmutableClassDef(OWNER, 1, "Ljava/lang/Object;", List.of(), null, annotations, List.of(f), methods))));
    }
    Method getter(boolean published) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 1, 3));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 2, 1));
        b.addInstruction(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2, field));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        return make("access$100", List.of(OWNER), STR, AccessFlags.STATIC.getValue() | AccessFlags.SYNTHETIC.getValue() | (published ? AccessFlags.PUBLIC.getValue() : 0), b);
    }
    Method reader(boolean viaGetter, boolean escape) {
        var b = new MethodImplementationBuilder(3);
        if (viaGetter) {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 2, 0, 0, 0, 0, getter(false)));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        } else b.addInstruction(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2, field));
        if (escape) b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        else {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref(STR, "length", List.of(), "I")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        }
        return make("read", List.of(OWNER), escape ? STR : "I", 9, b);
    }
    Set<String> prove(List<Method> methods) { return new PrivateStringFields(dex(2, methods, Set.of()), Set.of()).provenFields(); }
    @Test public void privateVolatileFieldReadForContentIsProven() { assertEquals(Set.of(Signatures.of(field)), prove(List.of(reader(false, false)))); }
    @Test public void compilerGetterIsFollowedIntoEveryCaller() { assertEquals(Set.of(Signatures.of(field)), prove(List.of(getter(false), reader(true, false)))); }
    @Test public void returningAFieldOrGetterResultRetainsIdentity() {
        assertTrue(prove(List.of(reader(false, true))).isEmpty());
        assertTrue(prove(List.of(getter(false), reader(true, true))).isEmpty());
    }
    @Test public void publishedFieldOrGetterIsNotAssumedPrivate() {
        assertTrue(new PrivateStringFields(dex(1, List.of(reader(false, false)), Set.of()), Set.of()).provenFields().isEmpty());
        assertTrue(prove(List.of(getter(true), reader(true, false))).isEmpty());
    }
    @Test public void nativeOrActiveReflectionPreventsPrivateFieldSimplification() {
        Method nativeMethod = make("nativeObserve", List.of(), "V", 9 | AccessFlags.NATIVE.getValue(), null);
        assertTrue(prove(List.of(reader(false, false), nativeMethod)).isEmpty());
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/Class;", "getDeclaredFields", List.of(), "[Ljava/lang/reflect/Field;")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method reflective = make("observe", List.of("Ljava/lang/Class;"), "V", 9, b);
        assertTrue(prove(List.of(reader(false, false), reflective)).isEmpty());
        // Only a separately established dormant runtime set may exclude the reflection body.
        var d = dex(2, List.of(reader(false, false), reflective), Set.of());
        assertEquals(Set.of(Signatures.of(field)), new PrivateStringFields(d, Set.of(Signatures.of(reflective))).provenFields());
    }
    @Test public void encodedFieldReferenceAndGetterHandleBlockTheProof() {
        Annotation annotation = new ImmutableAnnotation(1, "LMetadata;", Set.of(new ImmutableAnnotationElement("field", new ImmutableFieldEncodedValue(field))));
        assertTrue(new PrivateStringFields(dex(2, List.of(reader(false, false)), Set.of(annotation)), Set.of()).provenFields().isEmpty());
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_METHOD_HANDLE, 0, new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC, getter(false))));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        assertTrue(prove(List.of(getter(false), reader(true, false), make("handle", List.of(), "Ljava/lang/invoke/MethodHandle;", 9, b))).isEmpty());
    }
    @Test public void wholeDexCleanupRestoresTheInitializerAndLeavesFieldFlagsUntouched() {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(Edits.constant(2, 1)); b.addInstruction(Edits.constant(3, "starting"));
        var helper = ReflectionCode.ref("LCache;", "known", List.of("I", STR), STR);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 3, 0, 0, 0, helper));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction22c(Opcode.IPUT_OBJECT, 0, 5, field)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var init = make("init", List.of(OWNER), "V", 9, b);
        var d = dex(2, List.of(init, getter(false), reader(true, false)), Set.of());
        var result = PrivateStringFields.clean(d.original(), d, new ReflectionModel(d), Map.of(Signatures.of(helper), false));
        assertEquals(1, result.edits());
        var output = new DexContext(result.dex());
        assertEquals(d.fields().get(Signatures.of(field)).getAccessFlags(), output.fields().get(Signatures.of(field)).getAccessFlags());
        boolean stored = false;
        for (var instruction : output.methods().get(Signatures.of(init)).getImplementation().getInstructions()) {
            assertNotEquals(Opcode.INVOKE_STATIC, instruction.getOpcode());
            if (instruction.getOpcode() == Opcode.IPUT_OBJECT) stored = true;
        }
        assertTrue(stored);
    }
    @Test public void storingIntoAProvenFieldDoesNotPermitOtherEscapes() {
        var b = new MethodImplementationBuilder(3);
        b.addInstruction(Edits.constant(0, "starting"));
        b.addInstruction(new BuilderInstruction22c(Opcode.IPUT_OBJECT, 0, 2, field));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method m = make("init", List.of(OWNER), "V", 9, b); var g = new CodeGraph(m.getImplementation());
        assertFalse(StringContentUses.onlyContent(g, new ReflectionTypes(m, g), 0));
        assertTrue(StringContentUses.onlyContent(g, new ReflectionTypes(m, g), 0, Set.of(Signatures.of(field))));
        var escaped = new MethodImplementationBuilder(3); escaped.addInstruction(Edits.constant(0, "starting"));
        escaped.addInstruction(new BuilderInstruction22c(Opcode.IPUT_OBJECT, 0, 2, field)); escaped.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        m = make("escape", List.of(OWNER), STR, 9, escaped); g = new CodeGraph(m.getImplementation());
        assertFalse(StringContentUses.onlyContent(g, new ReflectionTypes(m, g), 0, Set.of(Signatures.of(field))));
    }
}
