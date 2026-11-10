package me.naptila.deobfuscator.transformers.np.reflection;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Must reference types and exact wrapper factories, merged across normal and exception edges. */
final class ReflectionTypes {
    record Fact(String type, int boxing) { Fact(String type) { this(type, -1); } }
    private final Fact[][] before;
    ReflectionTypes(Method method, CodeGraph g) {
        before = new Fact[g.size()][]; if (g.size() == 0) return;
        int size = g.registers() + 1; Fact[] entry = new Fact[size];
        int words = AccessFlags.STATIC.isSet(method.getAccessFlags()) ? 0 : 1;
        for (var t : method.getParameterTypes()) words += ProxyInstructions.wide(t.toString()) ? 2 : 1;
        int register = g.registers() - words;
        if (!AccessFlags.STATIC.isSet(method.getAccessFlags())) entry[register++] = new Fact(method.getDefiningClass());
        for (var t : method.getParameterTypes()) { entry[register] = new Fact(t.toString()); register += ProxyInstructions.wide(t.toString()) ? 2 : 1; }
        before[0] = entry; ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0); BitSet queued = new BitSet(); queued.set(0);
        int budget = Math.max(10000, g.size() * 256);
        while (!work.isEmpty()) {
            if (--budget == 0) throw new IllegalStateException("Reflection types did not converge");
            int at = work.removeFirst(); queued.clear(at); Fact[] state = before[at], out = state.clone();
            Instruction i = g.at(at); Opcode op = i.getOpcode(); String name = op.name; Fact pending = out[g.registers()]; out[g.registers()] = null;
            int a = i instanceof OneRegisterInstruction r ? r.getRegisterA() : -1;
            if (op.setsRegister()) { out[a] = null; if (op.setsWideRegister()) out[a + 1] = null; }
            if (name.startsWith("move-result")) out[a] = pending;
            else if (op == Opcode.MOVE_EXCEPTION) out[a] = new Fact("Ljava/lang/Throwable;");
            else if (name.startsWith("move") && i instanceof TwoRegisterInstruction r) out[a] = state[r.getRegisterB()];
            else if (name.startsWith("const-string")) out[a] = new Fact(ReflectionModel.STRING);
            else if (op == Opcode.CONST_CLASS) out[a] = new Fact("Ljava/lang/Class;");
            else if (name.startsWith("const") && i instanceof NarrowLiteralInstruction literal) out[a] = new Fact(literal.getNarrowLiteral() == 0 ? "null" : "I");
            else if (op == Opcode.CHECK_CAST || op == Opcode.NEW_INSTANCE || op == Opcode.NEW_ARRAY) {
                String type = ((TypeReference)((ReferenceInstruction)i).getReference()).getType();
                out[a] = op == Opcode.CHECK_CAST && state[a] != null && state[a].type().equals(type) ? state[a] : new Fact(type);
            } else if (op == Opcode.AGET_OBJECT) {
                Fact array = state[((ThreeRegisterInstruction)i).getRegisterB()];
                if (array != null && array.type().startsWith("[")) out[a] = new Fact(array.type().substring(1));
            } else if ((name.startsWith("iget") || name.startsWith("sget")) && i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f) out[a] = new Fact(f.getType());
            else if (name.startsWith("invoke") && i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference call) {
                String type = call.getReturnType();
                // A dispatcher result remains Object here: only an actual CHECK_CAST proves its type.
                if (!type.equals("V")) out[g.registers()] = new Fact(type);
                if (name.startsWith("invoke-static") && call.getName().equals("valueOf") && call.getParameterTypes().size() == 1) {
                    String primitive = call.getParameterTypes().get(0).toString();
                    if (!ReflectionCode.reference(primitive) && ReflectionCode.box(primitive).equals(call.getDefiningClass()) && type.equals(call.getDefiningClass())) out[g.registers()] = new Fact(type, at);
                }
            }
            for (int next : g.successors(at)) enqueue(next, out, work, queued);
            if (!g.handlers(at).isEmpty()) {
                Fact[] exception = state.clone(); exception[g.registers()] = null;
                BitSet writes = RegisterLiveness.writes(i); for (int reg = writes.nextSetBit(0); reg >= 0; reg = writes.nextSetBit(reg + 1)) exception[reg] = null;
                for (int next : g.handlers(at)) enqueue(next, exception, work, queued);
            }
        }
    }
    Fact get(int at, int register) { return before[at] == null ? null : before[at][register]; }
    private void enqueue(int at, Fact[] state, ArrayDeque<Integer> work, BitSet queued) {
        boolean changed = false;
        if (before[at] == null) { before[at] = state.clone(); changed = true; }
        else for (int r = 0; r < state.length; r++) {
            Fact a = before[at][r], b = state[r], merged;
            if (Objects.equals(a, b)) continue;
            if (a == null || b == null) merged = null;
            else if (a.type().equals(b.type())) merged = new Fact(a.type());
            else if (a.type().equals("null") && ReflectionCode.reference(b.type())) merged = new Fact(b.type());
            else if (b.type().equals("null") && ReflectionCode.reference(a.type())) merged = new Fact(a.type());
            else if (ReflectionCode.reference(a.type()) && ReflectionCode.reference(b.type())) merged = new Fact(ReflectionModel.OBJECT);
            else merged = null;
            if (!Objects.equals(a, merged)) { before[at][r] = merged; changed = true; }
        }
        if (changed && !queued.get(at)) { queued.set(at); work.add(at); }
    }
}
