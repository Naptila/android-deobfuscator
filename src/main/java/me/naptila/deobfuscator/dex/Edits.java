package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.OffsetInstruction;
import org.jf.dexlib2.iface.instruction.PayloadInstruction;

/** Edits use labels created before mutation and descending snapshot indices. */
public final class Edits {
    public record Edit(int index, boolean insertBefore, List<BuilderInstruction> instructions) {
        public Edit { instructions = List.copyOf(instructions); if (instructions.isEmpty()) throw new IllegalArgumentException("Empty edit"); }
    }
    private Edits() {}
    /** Independent builder instruction for cloning a non-branching transition prefix. */
    public static BuilderInstruction copy(Instruction instruction, int registers) {
        if (instruction instanceof OffsetInstruction || instruction instanceof PayloadInstruction)
            throw new IllegalArgumentException("Relative targets require explicit label remapping");
        return new MutableMethodImplementation(new ImmutableMethodImplementation(registers, List.of(instruction), List.of(), List.of()))
                .getInstructions().get(0);
    }
    public static BuilderInstruction constant(int register, Object value) {
        if (register < 0 || register > 255) throw new IllegalArgumentException("Constant destination exceeds 8 bits");
        if (value instanceof Integer n) return new BuilderInstruction31i(Opcode.CONST, register, n);
        if (value instanceof String s) return new BuilderInstruction31c(Opcode.CONST_STRING_JUMBO, register, new ImmutableStringReference(s));
        throw new IllegalArgumentException("Unknown constant");
    }
    public static BuilderInstruction jump(MutableMethodImplementation code, int target) {
        return new BuilderInstruction30t(Opcode.GOTO_32, code.newLabelForIndex(target));
    }
    public static void apply(MutableMethodImplementation code, List<Edit> edits) {
        List<Edit> sorted = new ArrayList<>(edits);
        sorted.sort(Comparator.comparingInt(Edit::index).reversed().thenComparing(Edit::insertBefore));
        for (Edit edit : sorted) {
            if (edit.insertBefore()) {
                // Existing labels stay attached to the old instruction: only fallthrough executes this edge block.
                for (int k = 0; k < edit.instructions().size(); k++) code.addInstruction(edit.index() + k, edit.instructions().get(k));
            } else {
                code.replaceInstruction(edit.index(), edit.instructions().get(0));
                for (int k = 1; k < edit.instructions().size(); k++) code.addInstruction(edit.index() + k, edit.instructions().get(k));
            }
        }
        if (!edits.isEmpty()) BranchRelaxation.run(code);
    }
}
