package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction;

/** Instruction-level CFG; payload offsets are relative to the referring switch. */
public final class CodeGraph {
    private final List<Instruction> instructions = new ArrayList<>();
    private final List<Integer> addresses = new ArrayList<>();
    private final Map<Integer, Integer> indices = new HashMap<>();
    private final List<List<Integer>> successors = new ArrayList<>();
    private final List<List<Integer>> handlers = new ArrayList<>();
    /** Ordered typed handlers, including coverage of non-throwing instructions. */
    public record Handler(String type, int target) {}
    private final List<List<Handler>> protection = new ArrayList<>();
    private final Set<Integer> leaders = new TreeSet<>();
    private final int registers;

    public CodeGraph(MethodImplementation code) {
        registers = code.getRegisterCount();
        int address = 0;
        for (Instruction insn : code.getInstructions()) {
            indices.put(address, instructions.size()); addresses.add(address);
            instructions.add(ImmutableInstruction.of(insn)); address += insn.getCodeUnits();
            successors.add(new ArrayList<>()); handlers.add(new ArrayList<>()); protection.add(new ArrayList<>());
        }
        if (!instructions.isEmpty()) leaders.add(0);
        for (int i = 0; i < size(); i++) {
            Instruction insn = at(i); Opcode op = insn.getOpcode();
            if (isPayload(i)) { leaders.add(i); if (i + 1 < size()) leaders.add(i + 1); continue; }
            List<Integer> next = successors.get(i);
            if (isGoto(op) || isIf(op)) {
                next.add(index(address(i) + ((OffsetInstruction) insn).getCodeOffset()));
                leaders.addAll(next);
            } else if (isSwitch(op)) {
                for (SwitchElement element : payload(i).getSwitchElements())
                    next.add(index(address(i) + element.getOffset()));
                leaders.addAll(next);
            }
            if (op.canContinue() && i + 1 < size()) next.add(i + 1);
            if (isGoto(op) || isIf(op) || isSwitch(op) || !op.canContinue()) {
                if (i + 1 < size()) leaders.add(i + 1);
            }
        }
        for (var block : code.getTryBlocks()) {
            int start = Collections.binarySearch(addresses, block.getStartCodeAddress());
            if (start < 0) start = -start - 1;
            int end = block.getStartCodeAddress() + block.getCodeUnitCount();
            for (var handler : block.getExceptionHandlers()) {
                int target = index(handler.getHandlerCodeAddress()); leaders.add(target);
                for (int i = start; i < size() && address(i) < end; i++) {
                        protection.get(i).add(new Handler(handler.getExceptionType(), target));
                        if (at(i).getOpcode().canThrow()) handlers.get(i).add(target);
                }
            }
        }
    }
    public int size() { return instructions.size(); }
    public int registers() { return registers; }
    public Instruction at(int i) { return instructions.get(i); }
    public int address(int i) { return addresses.get(i); }
    public int index(int address) {
        Integer i = indices.get(address);
        if (i == null) throw new IllegalArgumentException("Invalid instruction address: " + address);
        return i;
    }
    public boolean isPayload(int i) { return at(i) instanceof PayloadInstruction; }
    public Set<Integer> leaders() { return Collections.unmodifiableSet(leaders); }
    public List<Integer> successors(int i) { return Collections.unmodifiableList(successors.get(i)); }
    public List<Integer> handlers(int i) { return Collections.unmodifiableList(handlers.get(i)); }
    public List<Handler> protection(int i) { return Collections.unmodifiableList(protection.get(i)); }
    public int payloadIndex(int i) { return index(address(i) + ((OffsetInstruction) at(i)).getCodeOffset()); }
    public SwitchPayload payload(int i) { return (SwitchPayload) at(payloadIndex(i)); }
    public int switchTarget(int i, int key) {
        for (SwitchElement element : payload(i).getSwitchElements())
            if (element.getKey() == key) return index(address(i) + element.getOffset());
        if (i + 1 >= size()) throw new IllegalArgumentException("Missing switch default");
        return i + 1;
    }
    public static boolean isGoto(Opcode op) { return op == Opcode.GOTO || op == Opcode.GOTO_16 || op == Opcode.GOTO_32; }
    public static boolean isSwitch(Opcode op) { return op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH; }
    public static boolean isIf(Opcode op) { return op.name.startsWith("if-"); }
}
