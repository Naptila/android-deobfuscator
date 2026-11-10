package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.Signatures;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.iface.value.IntEncodedValue;
import org.jf.dexlib2.iface.value.LongEncodedValue;

/** Independent concrete interpreter for numeric fixture methods; unsupported operations fail. */
final class NpNumericInterpreter {
    private final DexContext dex;
    private final Map<String, Object> fields = new HashMap<>();
    private int allocationAttempts;
    NpNumericInterpreter(DexFile input) {
        dex = new DexContext(input);
        for (Field field : dex.fields().values()) {
            if (field.getInitialValue() instanceof IntEncodedValue n) fields.put(Signatures.of(field), n.getValue());
            if (field.getInitialValue() instanceof LongEncodedValue n) fields.put(Signatures.of(field), n.getValue());
        }
    }
    Object field(String signature) { return fields.get(signature); }
    int allocationAttempts() { return allocationAttempts; }
    Object run(String signature, Object... arguments) { return execute(dex.findMethod(signature).orElseThrow(), arguments, 0); }
    private Object execute(Method method, Object[] arguments, int depth) {
        if (depth > 8) throw new AssertionError("Call depth exceeded");
        CodeGraph graph = new CodeGraph(method.getImplementation());
        Map<Integer, Object> registers = new HashMap<>();
        int words = method.getParameterTypes().stream().mapToInt(t -> t.equals("J") || t.equals("D") ? 2 : 1).sum();
        int next = graph.registers() - words;
        for (int i = 0; i < arguments.length; i++) {
            registers.put(next, arguments[i]);
            String type = method.getParameterTypes().get(i).toString(); next += type.equals("J") || type.equals("D") ? 2 : 1;
        }
        int pc = 0; Object pending = null;
        for (int steps = 0; steps < 100000; steps++) {
            Instruction i = graph.at(pc); Opcode op = i.getOpcode();
            Object prior = pending; pending = null;
            int a = i instanceof OneRegisterInstruction one ? one.getRegisterA() : -1;
            int b = i instanceof TwoRegisterInstruction two ? two.getRegisterB() : -1;
            if (op == Opcode.NOP) { pc++; continue; }
            if (op == Opcode.RETURN || op == Opcode.RETURN_WIDE || op == Opcode.RETURN_OBJECT) {
                Object value = required(registers, a);
                if (method.getReturnType().equals("F")) return asFloat(value);
                if (method.getReturnType().equals("D")) return asDouble(value);
                return value;
            }
            if (CodeGraph.isGoto(op)) { pc = graph.successors(pc).get(0); continue; }
            if (CodeGraph.isSwitch(op)) { pc = graph.switchTarget(pc, (Integer)required(registers,a)); continue; }
            if (CodeGraph.isIf(op)) {
                Object leftValue = required(registers, a), rightValue = b < 0 ? 0 : required(registers, b);
                if (!(leftValue instanceof Integer) || !(rightValue instanceof Integer)) {
                    boolean leftNull = leftValue == null || leftValue instanceof Integer n && n == 0;
                    boolean rightNull = rightValue == null || rightValue instanceof Integer n && n == 0;
                    boolean equal = leftValue == rightValue || leftNull && rightNull;
                    boolean take = switch (op) {
                        case IF_EQ, IF_EQZ -> equal;
                        case IF_NE, IF_NEZ -> !equal;
                        default -> throw new AssertionError("Unsupported reference comparison: " + op);
                    };
                    pc = take ? graph.successors(pc).get(0) : pc + 1; continue;
                }
                int left = (Integer)leftValue, right = (Integer)rightValue;
                boolean take = switch (op) {
                    case IF_EQ, IF_EQZ -> left == right;
                    case IF_NE, IF_NEZ -> left != right;
                    case IF_LT, IF_LTZ -> left < right;
                    case IF_LE, IF_LEZ -> left <= right;
                    case IF_GT, IF_GTZ -> left > right;
                    case IF_GE, IF_GEZ -> left >= right;
                    default -> throw new AssertionError(op);
                };
                pc = take ? graph.successors(pc).get(0) : pc + 1; continue;
            }
            switch (op) {
                case CONST_4, CONST_16, CONST, CONST_HIGH16 -> registers.put(a, ((NarrowLiteralInstruction)i).getNarrowLiteral());
                case CONST_WIDE_16, CONST_WIDE_32, CONST_WIDE, CONST_WIDE_HIGH16 -> registers.put(a, ((WideLiteralInstruction)i).getWideLiteral());
                case CONST_STRING, CONST_STRING_JUMBO -> registers.put(a, ((StringReference)((ReferenceInstruction)i).getReference()).getString());
                case MOVE, MOVE_FROM16, MOVE_16, MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16,
                        MOVE_WIDE, MOVE_WIDE_FROM16, MOVE_WIDE_16 -> registers.put(a, required(registers,b));
                case MOVE_RESULT, MOVE_RESULT_OBJECT, MOVE_RESULT_WIDE -> registers.put(a, Objects.requireNonNull(prior));
                case NEW_ARRAY -> {
                    allocationAttempts++;
                    String type = ((TypeReference)((ReferenceInstruction)i).getReference()).getType();
                    registers.put(a, newArray(type, (Integer)required(registers,b)));
                }
                case FILLED_NEW_ARRAY, FILLED_NEW_ARRAY_RANGE -> {
                    allocationAttempts++;
                    String type = ((TypeReference)((ReferenceInstruction)i).getReference()).getType();
                    int[] sources = ConstantEvaluator.arguments(i);
                    Object array = newArray(type, sources.length);
                    for (int n = 0; n < sources.length; n++) {
                        Object value = required(registers,sources[n]);
                        if (array instanceof Object[] && value instanceof Integer zero && zero == 0) value = null;
                        java.lang.reflect.Array.set(array,n,value);
                    }
                    pending = array;
                }
                case ARRAY_LENGTH -> registers.put(a, java.lang.reflect.Array.getLength(required(registers,b)));
                case AGET, AGET_OBJECT -> registers.put(a, java.lang.reflect.Array.get(required(registers,b),
                        (Integer)required(registers,((ThreeRegisterInstruction)i).getRegisterC())));
                case NEG_INT -> registers.put(a, -(Integer)required(registers, b));
                case NOT_INT -> registers.put(a, ~(Integer)required(registers, b));
                case NEG_LONG -> registers.put(a, -(Long)required(registers, b));
                case NEG_FLOAT -> registers.put(a, -asFloat(required(registers, b)));
                case NEG_DOUBLE -> registers.put(a, -asDouble(required(registers, b)));
                case NOT_LONG -> registers.put(a, ~(Long)required(registers, b));
                case INT_TO_BYTE -> registers.put(a, (int)(byte)(int)(Integer)required(registers, b));
                case AGET_BYTE -> {
                    try {
                        registers.put(a, (int)((byte[])required(registers, b))[
                                (Integer)required(registers, ((ThreeRegisterInstruction)i).getRegisterC())]);
                    } catch (NullPointerException | ArrayIndexOutOfBoundsException error) {
                        int handler = -1;
                        for (var candidate : graph.protection(pc)) {
                            if (catches(candidate.type(), error)) {
                                handler = candidate.target(); break;
                            }
                        }
                        if (handler < 0) throw error;
                        pending = error; pc = handler; continue;
                    }
                }
                case MOVE_EXCEPTION -> registers.put(a, Objects.requireNonNull(prior));
                case INT_TO_LONG -> registers.put(a, ((Integer)required(registers, b)).longValue());
                case INT_TO_DOUBLE -> registers.put(a, ((Integer)required(registers, b)).doubleValue());
                case INT_TO_FLOAT -> registers.put(a, ((Integer)required(registers, b)).floatValue());
                case SGET, SGET_WIDE -> registers.put(a, Objects.requireNonNull(fields.get(Signatures.of((FieldReference)((ReferenceInstruction)i).getReference()))));
                case SPUT, SPUT_WIDE -> fields.put(Signatures.of((FieldReference)((ReferenceInstruction)i).getReference()), required(registers,a));
                case INVOKE_STATIC, INVOKE_STATIC_RANGE -> {
                    MethodReference ref = (MethodReference)((ReferenceInstruction)i).getReference();
                    int[] regs = ConstantEvaluator.arguments(i); Object[] args = new Object[ref.getParameterTypes().size()]; int r = 0;
                    for (int j = 0; j < args.length; j++) {
                        args[j] = required(registers,regs[r]); String type = ref.getParameterTypes().get(j).toString(); r += type.equals("J") || type.equals("D") ? 2 : 1;
                    }
                    pending = execute(dex.findMethod(Signatures.of(ref)).orElseThrow(), args, depth + 1);
                }
                case INVOKE_VIRTUAL, INVOKE_VIRTUAL_RANGE -> {
                    String sig = Signatures.of((MethodReference)((ReferenceInstruction)i).getReference());
                    if (!sig.equals("Ljava/lang/Object;->hashCode()I") && !sig.equals("Ljava/lang/String;->hashCode()I")) throw new AssertionError(sig);
                    pending = ((String)required(registers,ConstantEvaluator.arguments(i)[0])).hashCode();
                }
                default -> {
                    String name = op.name;
                    int leftReg = name.endsWith("/2addr") ? a : b;
                    Object left = required(registers,leftReg), right;
                    if (i instanceof NarrowLiteralInstruction literal) right = literal.getNarrowLiteral();
                    else right = required(registers,i instanceof ThreeRegisterInstruction three ? three.getRegisterC() : b);
                    Object result;
                    if (name.contains("-int")) {
                        int x = (Integer)left, y = (Integer)right;
                        result = switch (name.split("-")[0]) {
                            case "add" -> x + y; case "sub" -> x - y; case "rsub" -> y - x;
                            case "mul" -> x * y; case "div" -> x / y; case "rem" -> x % y;
                            case "xor" -> x ^ y; case "and" -> x & y; case "or" -> x | y;
                            default -> throw new AssertionError(op);
                        };
                    } else if (name.contains("-long")) {
                        long x = (Long)left, y = (Long)right;
                        result = switch (name.split("-")[0]) {
                            case "add" -> x + y; case "sub" -> x - y; case "mul" -> x * y;
                            case "and" -> x & y; case "or" -> x | y; case "xor" -> x ^ y; default -> throw new AssertionError(op);
                        };
                    } else if (name.contains("-float")) {
                        float x = asFloat(left), y = asFloat(right);
                        result = switch (name.split("-")[0]) {
                            case "add" -> x + y; case "sub" -> x - y; case "mul" -> x * y;
                            case "div" -> x / y; case "rem" -> x % y; default -> throw new AssertionError(op);
                        };
                    } else if (name.contains("-double")) {
                        double x = asDouble(left), y = asDouble(right);
                        result = switch (name.split("-")[0]) {
                            case "add" -> x + y; case "sub" -> x - y; case "mul" -> x * y;
                            case "div" -> x / y; case "rem" -> x % y; default -> throw new AssertionError(op);
                        };
                    } else throw new AssertionError("Unsupported fixture instruction: " + op);
                    registers.put(a, result);
                }
            }
            pc++;
        }
        throw new AssertionError("Execution limit: " + Signatures.of(method));
    }
    private static Object required(Map<Integer,Object> state, int register) {
        if (!state.containsKey(register)) throw new AssertionError("Unknown register " + register);
        return state.get(register);
    }
    private static double asDouble(Object value) { return value instanceof Long bits ? Double.longBitsToDouble(bits) : (Double)value; }
    private static float asFloat(Object value) { return value instanceof Integer bits ? Float.intBitsToFloat(bits) : (Float)value; }
    private static Object newArray(String type, int size) {
        return switch (type) {
            case "[I" -> new int[size];
            case "[Ljava/lang/String;" -> new String[size];
            case "[Ljava/lang/Object;" -> new Object[size];
            default -> throw new AssertionError("Unsupported fixture array: " + type);
        };
    }
    private static boolean catches(String descriptor, Throwable error) {
        if (descriptor == null) return true;
        for (Class<?> ancestor = error.getClass(); ancestor != null; ancestor = ancestor.getSuperclass())
            if (descriptor.equals("L" + ancestor.getName().replace('.', '/') + ";")) return true;
        return false;
    }
}
