package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.ImmutableDexFile;

/** Immutable original-input snapshot, shared by all method transactions in one run. */
public final class DexContext {
    private final ImmutableDexFile original;
    private final Map<String, ClassDef> classes;
    private final Map<String, Method> methods;
    private final Map<String, Field> fields;
    private final Map<Class<?>, Object> analyses = new HashMap<>();
    private final TransformationEvidence evidence = new TransformationEvidence();

    /** Mutable transaction journal, deliberately separate from immutable input analyses. */
    public TransformationEvidence evidence() { return evidence; }

    /** Input-scoped analysis cache. Values must describe only this immutable original input. */
    public synchronized <T> T analysis(Class<T> type, java.util.function.Function<DexContext, T> factory) {
        if (!analyses.containsKey(type)) analyses.put(type, Objects.requireNonNull(factory.apply(this)));
        return type.cast(analyses.get(type));
    }

    public DexContext(DexFile dex) {
        original = ImmutableDexFile.of(dex);
        Map<String, ClassDef> classIndex = new TreeMap<>();
        Map<String, Method> methodIndex = new TreeMap<>();
        Map<String, Field> fieldIndex = new TreeMap<>();
        for (ClassDef cls : original.getClasses()) {
            classIndex.put(cls.getType(), cls);
            for (Method method : cls.getMethods()) methodIndex.put(Signatures.of(method), method);
            for (Field field : cls.getFields()) fieldIndex.put(Signatures.of(field), field);
        }
        classes = Collections.unmodifiableMap(classIndex);
        methods = Collections.unmodifiableMap(methodIndex);
        fields = Collections.unmodifiableMap(fieldIndex);
    }

    public DexFile original() { return original; }
    public Map<String, ClassDef> classes() { return classes; }
    public Map<String, Method> methods() { return methods; }
    public Map<String, Field> fields() { return fields; }
    public Optional<ClassDef> findClass(String descriptor) { return Optional.ofNullable(classes.get(descriptor)); }
    public Optional<Method> findMethod(String signature) { return Optional.ofNullable(methods.get(signature)); }
    public Optional<Field> findField(String signature) { return Optional.ofNullable(fields.get(signature)); }
}
