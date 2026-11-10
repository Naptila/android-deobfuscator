package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.Signatures;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;

final class Fixtures {
    static final String DECODE = "Lsample/Crypto;->decode(Ljava/lang/String;I)Ljava/lang/String;";
    static final ImmutableMethodReference HASH = new ImmutableMethodReference("Ljava/lang/String;", "hashCode", List.of(), "I");
    static final ImmutableMethodReference NP_HASH = new ImmutableMethodReference("Lsample/ZHash;", "hash", List.of("Ljava/lang/Object;"), "I");
    static final ImmutableMethodReference DECRYPT = new ImmutableMethodReference("Lsample/Crypto;", "decode", List.of("Ljava/lang/String;", "I"), "Ljava/lang/String;");
    private Fixtures() {}
    static void integer(MethodImplementationBuilder b, int reg, int value) { b.addInstruction(new BuilderInstruction31i(Opcode.CONST, reg, value)); }
    static void string(MethodImplementationBuilder b, int reg, String value) { b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, reg, new ImmutableStringReference(value))); }
    static void go(MethodImplementationBuilder b, String label) { b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel(label))); }
    static Method method(String name, List<ImmutableMethodParameter> params, String ret, MethodImplementation code) {
        return new ImmutableMethod("Lsample/Test;", name, params, ret, AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), code);
    }
    static DexFile dex(Method... methods) {
        return new ImmutableDexFile(Opcodes.forApi(28), List.of(new ImmutableClassDef("Lsample/Test;", AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", List.of(), "Test.java", Set.of(), List.of(), List.of(methods))));
    }
    /** NP-style hash wrapper, shared by the synthetic dispatcher integration cases. */
    static DexFile npDex(Method... methods) {
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "hashCode", List.of(), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method hash = new ImmutableMethod(NP_HASH.getDefiningClass(), NP_HASH.getName(),
                List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)), "I",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        var classes = new ArrayList<ClassDef>(dex(methods).getClasses());
        classes.add(new ImmutableClassDef(NP_HASH.getDefiningClass(), AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(hash)));
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    static Method first(DexFile dex) { return dex.getClasses().iterator().next().getMethods().iterator().next(); }
    static Method flattened(boolean expandedXor, boolean fallthroughEntry, boolean tryRegion) {
        return flattened(expandedXor, fallthroughEntry, tryRegion, false);
    }
    static void stateString(MethodImplementationBuilder b, String state, boolean encrypted) {
        if (!encrypted) { string(b, 0, state); return; }
        char[] chars = state.toCharArray();
        for (int i = 0; i < chars.length; i++) chars[i] ^= 73;
        string(b, 0, new String(chars)); integer(b, 4, 73);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 4, 0, 0, 0, DECRYPT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
    }
    static void dispatcherState(MethodImplementationBuilder b, String state, boolean encrypted, boolean expandedXor) {
        stateString(b, state, encrypted);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, NP_HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        if (expandedXor) {
            integer(b, 4, 937);
            b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 3, 1, 4));
            b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 5, 2, 4));
            b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 3, 3, 5));
        } else b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 3, 1, 2));
    }
    static Method flattened(boolean expandedXor, boolean fallthroughEntry, boolean tryRegion, boolean encrypted) {
        MethodImplementationBuilder b = new MethodImplementationBuilder(7);
        int key = -123456789;
        integer(b, 1, key); dispatcherState(b, "entry", encrypted, expandedXor);
        if (!fallthroughEntry) go(b, "dispatch");
        b.addLabel("dispatch");
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 3, b.getLabel("payload")));
        go(b, "dispatch");
        b.addLabel("entry");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 6, b.getLabel("false")));
        dispatcherState(b, "yes", encrypted, expandedXor); go(b, "dispatch");
        b.addLabel("false"); dispatcherState(b, "no", encrypted, expandedXor); go(b, "dispatch");
        b.addLabel("yes"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        b.addLabel("no"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        b.addLabel("end");
        if (tryRegion) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            integer(b, 2, -1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
            b.addCatch("Ljava/lang/Exception;", b.getLabel("dispatch"), b.getLabel("end"), b.getLabel("handler"));
        }
        b.addLabel("payload");
        List<SwitchLabelElement> elements = new ArrayList<>();
        for (String state : List.of("entry", "yes", "no")) elements.add(new SwitchLabelElement(state.hashCode() ^ key, b.getLabel(state)));
        elements.sort(Comparator.comparingInt(e -> e.key)); b.addInstruction(new BuilderSparseSwitchPayload(elements));
        return method("f", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }
    static Method encryptedString(boolean unknownKey) {
        MethodImplementationBuilder b = new MethodImplementationBuilder(3);
        char[] plain = "中文🙂 secret".toCharArray();
        for (int i = 0; i < plain.length; i++) plain[i] ^= 73;
        string(b, 0, new String(plain));
        if (!unknownKey) integer(b, 2, 73);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 2, 0, 0, 0, DECRYPT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        return method("text", unknownKey ? List.of(new ImmutableMethodParameter("I", Set.of(), "key")) : List.of(), "Ljava/lang/String;", b.getMethodImplementation());
    }
    /** Independent control-flow execution of the supported fixture subset, with a step cap. */
    static Object execute(Method method, int input) {
        CodeGraph graph = new CodeGraph(method.getImplementation()); Constants state = new Constants();
        if (!method.getParameters().isEmpty()) state.put(graph.registers() - 1, input);
        int pc = 0;
        for (int steps = 0; steps < 10000; steps++) {
            Instruction insn = graph.at(pc); Opcode op = insn.getOpcode();
            if (op == Opcode.RETURN || op == Opcode.RETURN_OBJECT) return state.get(((OneRegisterInstruction) insn).getRegisterA());
            if (CodeGraph.isGoto(op)) { pc = graph.successors(pc).get(0); continue; }
            if (CodeGraph.isSwitch(op)) { pc = graph.switchTarget(pc, (Integer)state.get(((OneRegisterInstruction)insn).getRegisterA())); continue; }
            if (op == Opcode.IF_LEZ) {
                int value = (Integer)state.get(((OneRegisterInstruction)insn).getRegisterA());
                pc = value <= 0 ? graph.successors(pc).get(0) : pc + 1; continue;
            }
            if (op == Opcode.INVOKE_STATIC) {
                int[] regs = ConstantEvaluator.arguments(insn);
                if (Signatures.of((org.jf.dexlib2.iface.reference.MethodReference)((ReferenceInstruction)insn).getReference()).equals(Signatures.of(NP_HASH))) {
                    state.result(((String)state.get(regs[0])).hashCode()); pc++; continue;
                }
                String encoded = (String)state.get(regs[0]); int key = (Integer)state.get(regs[1]);
                StringBuilder clear = new StringBuilder();
                for (int i = 0; i < encoded.length(); i++) clear.append((char)(encoded.charAt(i) ^ key));
                state.result(clear.toString());
            } else if (!ConstantEvaluator.step(insn, state)) throw new AssertionError("Unsupported fixture instruction " + op);
            pc++;
        }
        throw new AssertionError("Fixture execution did not terminate");
    }
}
