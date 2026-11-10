package me.naptila.deobfuscator.transformers.np.reflection;

import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.MemberResolver;
import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;

/** Small, named call adapters. Failed argument guards use the original reflection semantics. */
final class ReflectionCode {
    static String box(String type) {
        return switch (type) {
            case "Z" -> "Ljava/lang/Boolean;"; case "B" -> "Ljava/lang/Byte;"; case "S" -> "Ljava/lang/Short;";
            case "C" -> "Ljava/lang/Character;"; case "I" -> "Ljava/lang/Integer;"; case "J" -> "Ljava/lang/Long;";
            case "F" -> "Ljava/lang/Float;"; case "D" -> "Ljava/lang/Double;"; default -> type;
        };
    }
    static String unbox(String type) {
        return switch (type) { case "Z" -> "booleanValue"; case "B" -> "byteValue"; case "S" -> "shortValue";
            case "C" -> "charValue"; case "I" -> "intValue"; case "J" -> "longValue"; case "F" -> "floatValue"; case "D" -> "doubleValue"; default -> throw new IllegalArgumentException(type); };
    }
    static boolean reference(String type) { return type.startsWith("L") || type.startsWith("["); }
    static ImmutableMethodReference ref(String owner, String name, List<String> params, String ret) { return new ImmutableMethodReference(owner, name, params, ret); }
    static void invoke(MethodImplementationBuilder b, Opcode op, int start, int count, MethodReference ref) {
        b.addInstruction(new BuilderInstruction3rc(op, start, count, ref));
    }
    static void cast(MethodImplementationBuilder b, int reg, String type) { b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, reg, new ImmutableTypeReference(type))); }
    static void branch(MethodImplementationBuilder b, Opcode op, int reg, String label) { b.addInstruction(new BuilderInstruction21t(op, reg, b.getLabel(label))); }
    static Method method(String owner, String name, ReflectionModel.Entry entry, MethodImplementationBuilder b) {
        return new ImmutableMethod(owner, name, entry.dispatcher().getParameters(), ReflectionModel.OBJECT,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.SYNTHETIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    static Method string(String name, ReflectionModel.Entry entry) {
        var b = new MethodImplementationBuilder(4);
        // The incoming ID is deliberately ignored; this getter has one fixed cache slot.
        b.addInstruction(Edits.constant(0, entry.id()));
        invoke(b, Opcode.INVOKE_STATIC_RANGE, 0, 1, entry.get());
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        branch(b, Opcode.IF_NEZ, 1, "return");
        b.addInstruction(Edits.constant(1, entry.target().text()));
        if (!entry.target().interned()) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, new ImmutableTypeReference(ReflectionModel.STRING)));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 2, 1, 0, 0, 0, ref(ReflectionModel.STRING, "<init>", List.of(ReflectionModel.STRING), "V")));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 2));
        }
        invoke(b, Opcode.INVOKE_STATIC_RANGE, 0, 2, entry.put());
        b.addLabel("return"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        return method(entry.dispatcher().getDefiningClass(), name, entry, b);
    }
    static Method cachedString(String name, ReflectionModel.Entry entry) {
        var b = new MethodImplementationBuilder(4); // v2: cache key, v3: plaintext
        invoke(b, Opcode.INVOKE_STATIC_RANGE, 2, 1, entry.get());
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        cast(b, 0, ReflectionModel.STRING);
        branch(b, Opcode.IF_NEZ, 0, "return");
        if (!entry.target().interned()) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference(ReflectionModel.STRING)));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 0, 3, 0, 0, 0, ref(ReflectionModel.STRING, "<init>", List.of(ReflectionModel.STRING), "V")));
        } else b.addInstruction(ProxyInstructions.move(0, 3, ReflectionModel.STRING));
        b.addInstruction(ProxyInstructions.move(3, 0, ReflectionModel.STRING));
        invoke(b, Opcode.INVOKE_STATIC_RANGE, 2, 2, entry.put());
        b.addLabel("return"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        return new ImmutableMethod(entry.dispatcher().getDefiningClass(), name,
                List.of(new ImmutableMethodParameter("I", Set.of(), "id"), new ImmutableMethodParameter(ReflectionModel.STRING, Set.of(), "text")), ReflectionModel.STRING,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.SYNTHETIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    static Method typed(String owner, String name, Reference member, MemberResolver.Member resolved) {
        boolean isStatic = AccessFlags.STATIC.isSet(resolved.flags());
        MethodReference target = member instanceof MethodReference m ? m : null;
        FieldReference field = member instanceof FieldReference f ? f : null;
        List<String> params = new ArrayList<>();
        if (!isStatic) params.add(target != null ? target.getDefiningClass() : field.getDefiningClass());
        if (target != null) target.getParameterTypes().forEach(t -> params.add(t.toString()));
        int words = params.stream().mapToInt(t -> ProxyInstructions.wide(t) ? 2 : 1).sum();
        if (words > 255) return null;
        String result = target != null ? target.getReturnType() : field.getType();
        var b = new MethodImplementationBuilder(words + 2);
        if (target != null) {
            Opcode op = isStatic ? Opcode.INVOKE_STATIC_RANGE : AccessFlags.PRIVATE.isSet(resolved.flags()) ? Opcode.INVOKE_DIRECT_RANGE
                    : AccessFlags.INTERFACE.isSet(resolved.ownerFlags()) ? Opcode.INVOKE_INTERFACE_RANGE : Opcode.INVOKE_VIRTUAL_RANGE;
            invoke(b, op, 2, words, target);
            if (!result.equals("V")) b.addInstruction(new BuilderInstruction11x(reference(result) ? Opcode.MOVE_RESULT_OBJECT : ProxyInstructions.wide(result) ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT, 0));
        } else {
            String suffix = reference(result) ? "_OBJECT" : ProxyInstructions.wide(result) ? "_WIDE" : switch(result) { case "Z" -> "_BOOLEAN"; case "B" -> "_BYTE"; case "C" -> "_CHAR"; case "S" -> "_SHORT"; default -> ""; };
            Opcode op = Opcode.valueOf((isStatic ? "SGET" : "IGET") + suffix);
            b.addInstruction(isStatic ? new BuilderInstruction21c(op, 0, field) : new BuilderInstruction22c(op, 0, 2, field));
        }
        b.addInstruction(result.equals("V") ? new BuilderInstruction10x(Opcode.RETURN_VOID) : new BuilderInstruction11x(reference(result) ? Opcode.RETURN_OBJECT : ProxyInstructions.wide(result) ? Opcode.RETURN_WIDE : Opcode.RETURN, 0));
        return new ImmutableMethod(owner, name, params.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(), result,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.SYNTHETIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    static Method member(String owner, String name, ReflectionModel.Entry entry, MemberResolver.Member resolved) {
        Reference member = entry.target().member(); boolean isStatic = AccessFlags.STATIC.isSet(resolved.flags());
        MethodReference target = member instanceof MethodReference m ? m : null;
        FieldReference field = member instanceof FieldReference f ? f : null;
        List<String> params = target == null ? List.of() : target.getParameterTypes().stream().map(Object::toString).toList();
        int words = (isStatic ? 0 : 1) + params.stream().mapToInt(t -> ProxyInstructions.wide(t) ? 2 : 1).sum();
        int input = Math.max(8, words + 4), count = entry.dispatcher().getParameterTypes().size();
        if (input + count > 255 || words > 255) return null;
        var b = new MethodImplementationBuilder(input + count);
        String targetOwner = target != null ? target.getDefiningClass() : field.getDefiningClass();
        // v0..2 are temporaries; v3.. hold contiguous, typed target arguments.
        int dest = 3;
        if (!isStatic) {
            if (count < 2) return null;
            b.addInstruction(ProxyInstructions.move(2, input + 1, ReflectionModel.OBJECT));
            guard(b, 2, targetOwner, false, "receiver");
            b.addInstruction(ProxyInstructions.move(dest++, 2, targetOwner));
        }
        if (target != null) {
            if (count != 3) return null;
            b.addInstruction(ProxyInstructions.move(1, input + 2, "[Ljava/lang/Object;"));
            if (params.isEmpty()) branch(b, Opcode.IF_EQZ, 1, "invoke");
            else branch(b, Opcode.IF_EQZ, 1, "fallback");
            b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 0, 1));
            b.addInstruction(Edits.constant(2, params.size()));
            b.addInstruction(new BuilderInstruction22t(Opcode.IF_NE, 0, 2, b.getLabel("fallback")));
            for (int i = 0; i < params.size(); i++) {
                String type = params.get(i); b.addInstruction(Edits.constant(0, i));
                b.addInstruction(new BuilderInstruction23x(Opcode.AGET_OBJECT, 2, 1, 0));
                guard(b, 2, box(type), reference(type), "arg" + i);
                if (reference(type)) b.addInstruction(ProxyInstructions.move(dest, 2, type));
                else {
                    invoke(b, Opcode.INVOKE_VIRTUAL_RANGE, 2, 1, ref(box(type), unbox(type), List.of(), type));
                    b.addInstruction(new BuilderInstruction11x(ProxyInstructions.wide(type) ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT, dest));
                }
                dest += ProxyInstructions.wide(type) ? 2 : 1;
            }
        }
        b.addLabel("invoke"); String result = target != null ? target.getReturnType() : field.getType();
        if (target != null) {
            Opcode op = isStatic ? Opcode.INVOKE_STATIC_RANGE : AccessFlags.PRIVATE.isSet(resolved.flags()) ? Opcode.INVOKE_DIRECT_RANGE
                    : AccessFlags.INTERFACE.isSet(resolved.ownerFlags()) ? Opcode.INVOKE_INTERFACE_RANGE : Opcode.INVOKE_VIRTUAL_RANGE;
            invoke(b, op, 3, words, target);
            if (!result.equals("V")) b.addInstruction(new BuilderInstruction11x(reference(result) ? Opcode.MOVE_RESULT_OBJECT : ProxyInstructions.wide(result) ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT, 0));
        } else {
            String suffix = reference(result) ? "_OBJECT" : ProxyInstructions.wide(result) ? "_WIDE" : switch(result) { case "Z" -> "_BOOLEAN"; case "B" -> "_BYTE"; case "C" -> "_CHAR"; case "S" -> "_SHORT"; default -> ""; };
            Opcode op = Opcode.valueOf((isStatic ? "SGET" : "IGET") + suffix);
            b.addInstruction(isStatic ? new BuilderInstruction21c(op, 0, field) : new BuilderInstruction22c(op, 0, 3, field));
        }
        if (result.equals("V")) b.addInstruction(Edits.constant(0, 0));
        else if (!reference(result)) {
            invoke(b, Opcode.INVOKE_STATIC_RANGE, 0, ProxyInstructions.wide(result) ? 2 : 1, ref(box(result), "valueOf", List.of(result), box(result)));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        }
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (target != null || !isStatic) {
            b.addLabel("fallback");
            // No handler covers the real target: target IllegalArgumentException etc. must propagate.
            invoke(b, Opcode.INVOKE_STATIC_RANGE, input, count, entry.dispatcher());
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        return method(owner, name, entry, b);
    }
    private static void guard(MethodImplementationBuilder b, int reg, String type, boolean nullable, String label) {
        if (nullable) branch(b, Opcode.IF_EQZ, reg, label);
        b.addInstruction(new BuilderInstruction22c(Opcode.INSTANCE_OF, 0, reg, new ImmutableTypeReference(type)));
        branch(b, Opcode.IF_EQZ, 0, "fallback");
        b.addLabel(label); cast(b, reg, type);
    }
}
