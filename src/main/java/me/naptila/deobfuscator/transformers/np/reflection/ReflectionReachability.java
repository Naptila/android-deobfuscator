package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.AccessFlags;

/** Closed-world roots: all application methods and all initializers; only NP-reachable static helpers may be dormant. */
final class ReflectionReachability {
    static Set<String> dormant(DexContext original, DexContext output, ReflectionModel model) {
        Map<String, List<MethodReferences.Use>> originalEdges = edges(new MethodReferences(original));
        MemberResolver resolver = new MemberResolver(original, new LibraryTypes(List.of()));
        Set<String> runtime = new HashSet<>(); ArrayDeque<String> work = new ArrayDeque<>(model.dispatchers.keySet());
        while (!work.isEmpty()) {
            String next = work.removeFirst(); var method = original.methods().get(next);
            if (method == null || !AccessFlags.STATIC.isSet(method.getAccessFlags()) || !runtime.add(next)) continue;
            for (var use : originalEdges.getOrDefault(next, List.of())) {
                String target = Signatures.of(use.method()); work.add(target);
                // NP dispatchers can name inherited static helpers through a subclass.
                // Keep the declaring method in the original runtime closure as well.
                var resolved = resolver.resolve(use.method());
                if (resolved != null && original.classes().containsKey(resolved.owner()))
                    work.add(resolved.owner() + target.substring(target.indexOf("->")));
            }
        }
        // NP helper containers also contain unused alternative wrappers. Under the explicit
        // closed-world contract these static siblings have no external entry points.
        // Constructors, annotations, native methods and restored target classes remain roots.
        Set<String> owners = new HashSet<>(), targetOwners = new HashSet<>();
        for (String sig : runtime) owners.add(original.methods().get(sig).getDefiningClass());
        for (var entries : model.dispatchers.values()) for (var entry : entries.values()) {
            var member = entry.target().member();
            if (member instanceof org.jf.dexlib2.iface.reference.MethodReference m) targetOwners.add(m.getDefiningClass());
            if (member instanceof org.jf.dexlib2.iface.reference.FieldReference f) targetOwners.add(f.getDefiningClass());
        }
        for (String owner : owners) {
            var cls = original.classes().get(owner);
            if (cls == null || targetOwners.contains(owner) || !"Ljava/lang/Object;".equals(cls.getSuperclass())
                    || !cls.getInterfaces().isEmpty() || entryAnnotations(cls.getAnnotations()) || cls.getInstanceFields().iterator().hasNext()) continue;
            for (var m : cls.getMethods()) if (AccessFlags.STATIC.isSet(m.getAccessFlags()) && !entryAnnotations(m.getAnnotations())
                    && !m.getName().equals("main")) runtime.add(Signatures.of(m));
        }
        var references = new MethodReferences(output); Map<String, List<MethodReferences.Use>> edges = edges(references);
        Set<String> active = new HashSet<>();
        for (var m : output.methods().values()) {
            String sig = Signatures.of(m);
            if (!runtime.contains(sig) || m.getName().equals("<clinit>") || AccessFlags.NATIVE.isSet(m.getAccessFlags()) || entryAnnotations(m.getAnnotations()) || m.getParameters().stream().anyMatch(p -> entryAnnotations(p.getAnnotations())) || m.getName().equals("main")) work.add(sig);
        }
        // Metadata / handles can expose a helper without an ordinary invoke instruction.
        for (var use : references.uses()) if (!use.directCall() || !output.methods().containsKey(use.source())) work.add(Signatures.of(use.method()));
        while (!work.isEmpty()) {
            String next = work.removeFirst(); if (!active.add(next)) continue;
            for (var use : edges.getOrDefault(next, List.of())) {
                String target = Signatures.of(use.method()); work.add(target);
                if (!output.methods().containsKey(target)) for (String candidate : runtime) {
                    var method = output.methods().get(candidate);
                    if (method != null && MethodReferences.mayResolveTo(output, use.method(), method)) work.add(candidate);
                }
            }
        }
        runtime.removeAll(active); return Set.copyOf(runtime);
    }
    private static boolean entryAnnotations(Iterable<? extends org.jf.dexlib2.iface.Annotation> annotations) {
        for (var annotation : annotations) {
            boolean signatureMetadata = annotation.getVisibility() == org.jf.dexlib2.AnnotationVisibility.SYSTEM
                    && Set.of("Ldalvik/annotation/Throws;", "Ldalvik/annotation/Signature;").contains(annotation.getType());
            if (!signatureMetadata) return true;
        }
        return false;
    }
    private static Map<String, List<MethodReferences.Use>> edges(MethodReferences references) {
        Map<String, List<MethodReferences.Use>> result = new HashMap<>();
        for (var use : references.uses()) result.computeIfAbsent(use.source(), k -> new ArrayList<>()).add(use);
        return result;
    }
}
