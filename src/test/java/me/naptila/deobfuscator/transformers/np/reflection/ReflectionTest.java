package me.naptila.deobfuscator.transformers.np.reflection;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.junit.*;
import static org.junit.Assert.*;

public class ReflectionTest {
    DexFile input; DexContext dex; ReflectionModel model;
    @Before public void load() throws Exception {
        input = DexFiles.read(Path.of(getClass().getResource("/np-batch3/reflect.dex").toURI()));
        dex = new DexContext(input); model = new ReflectionModel(dex);
    }
    @Test public void mapsAllThreeDispatcherShapesOffline() {
        assertEquals(21, model.dispatchers.size());
        var entries = model.dispatchers.values().stream().flatMap(m -> m.values().stream()).toList();
        assertEquals(650, entries.size());
        assertEquals(429, entries.stream().filter(e -> e.target().text() != null).count());
        assertEquals(172, entries.stream().filter(e -> e.target().member() instanceof MethodReference).count());
        assertEquals(49, entries.stream().filter(e -> e.target().member() instanceof FieldReference).count());
    }
    @Test public void disabledWithoutExplicitRuntimeAssumption() {
        var result = new DexEngine(List.of(new ReflectionTransformer()), 3).transform(input);
        assertEquals(0, result.changedMethods()); assertEquals(0, result.dexEdits());
    }
    ReflectionModel.Entry stringEntry() {
        return model.dispatchers.values().stream().flatMap(m -> m.values().stream()).filter(e -> e.target().text() != null && !e.target().interned()).findFirst().orElseThrow();
    }
    @Test public void allocatedStringsRetainCacheAndDistinctAllocation() {
        var entry = stringEntry(); var method = ReflectionCode.string("probe", entry); var g = new CodeGraph(method.getImplementation());
        assertEquals(entry.id(), ((NarrowLiteralInstruction)g.at(0)).getNarrowLiteral());
        assertEquals(Signatures.of(entry.get()), Signatures.of(ReflectionModel.methodRef(g.at(1))));
        assertEquals(Opcode.IF_NEZ, g.at(3).getOpcode());
        assertEquals(Opcode.NEW_INSTANCE, g.at(5).getOpcode());
        assertEquals(Signatures.of(entry.put()), Signatures.of(ReflectionModel.methodRef(g.at(8))));
    }
    @Test public void highRegisterCallerShowsLiteralWithoutChangingStringIdentityHelper() {
        var entry = stringEntry(); var b = new MethodImplementationBuilder(342);
        b.addInstruction(Edits.constant(0, entry.id()));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, entry.dispatcher()));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method caller = new ImmutableMethod("Lprobe/Caller;", "large", List.of(), ReflectionModel.OBJECT, 9, Set.of(), Set.of(), b.getMethodImplementation());
        var transformer = new ReflectionTransformer(List.of(), true); transformer.prepare(dex);
        var context = new MethodContext(dex, caller); transformer.run(context);
        assertEquals(342, context.code().getRegisterCount());
        boolean literal = false, cache = false;
        for (var instruction : context.code().getInstructions()) if (instruction instanceof ReferenceInstruction r) {
            if (r.getReference() instanceof StringReference text && text.getString().equals(entry.target().text())) literal = true;
            if (r.getReference() instanceof MethodReference m && m.getName().equals("np$resolved$string")) cache = true;
        }
        assertTrue(literal); assertTrue(cache);
        var helper = new CodeGraph(ReflectionCode.cachedString("np$resolved$string", entry).getImplementation());
        boolean allocate = false;
        for (int n = 0; n < helper.size(); n++) if (helper.at(n).getOpcode() == Opcode.NEW_INSTANCE) allocate = true;
        assertTrue(allocate);
    }
    @Test public void unusedRuntimeSiblingBecomesActiveWhenAnApplicationCallerAppears() {
        // A fixed, unreferenced sibling avoids relying on which original NP wrappers
        // happen to be reachable through inherited symbolic owners in this fixture.
        Method template = dex.methods().values().stream().filter(m -> m.getImplementation() != null && AccessFlags.STATIC.isSet(m.getAccessFlags()))
                .filter(m -> { for (var instruction : m.getImplementation().getInstructions())
                    if (instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference target
                            && target.getDefiningClass().equals("Ljava/lang/reflect/Field;") && target.getName().equals("get")) return true;
                    return false; }).findFirst().orElseThrow();
        Method dormant = new ImmutableMethod(template.getDefiningClass(), "unusedReflectionSiblingForTest", template.getParameters(), template.getReturnType(),
                template.getAccessFlags(), Set.of(), template.getHiddenApiRestrictions(), template.getImplementation());
        List<ClassDef> scenarioClasses = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(methods::add);
            if (cls.getType().equals(dormant.getDefiningClass())) methods.add(dormant);
            scenarioClasses.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        DexContext scenario = new DexContext(new ImmutableDexFile(input.getOpcodes(), scenarioClasses));
        assertTrue(ReflectionReachability.dormant(scenario, scenario, model).contains(Signatures.of(dormant)));
        var b = new MethodImplementationBuilder(4);
        for (int reg = 0; reg < dormant.getParameterTypes().size(); reg++) b.addInstruction(Edits.constant(reg, 0));
        b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 0, dormant.getParameterTypes().size(), dormant));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method caller = new ImmutableMethod("Lprobe/RuntimeCaller;", "observe", List.of(), "V", 9, Set.of(), Set.of(), b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>(scenario.original().getClasses());
        classes.add(new ImmutableClassDef(caller.getDefiningClass(), 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller)));
        DexContext output = new DexContext(new ImmutableDexFile(input.getOpcodes(), classes));
        assertFalse(ReflectionReachability.dormant(scenario, output, model).contains(Signatures.of(dormant)));
        Annotation callback = new ImmutableAnnotation(AnnotationVisibility.RUNTIME, "Lprobe/Callback;", Set.of());
        Method annotated = new ImmutableMethod(dormant.getDefiningClass(), dormant.getName(), dormant.getParameters(), dormant.getReturnType(),
                dormant.getAccessFlags(), Set.of(callback), dormant.getHiddenApiRestrictions(), dormant.getImplementation());
        List<ClassDef> metadataClasses = new ArrayList<>();
        for (ClassDef cls : scenario.original().getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method m : cls.getMethods()) methods.add(Signatures.of(m).equals(Signatures.of(dormant)) ? annotated : m);
            metadataClasses.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        assertFalse(ReflectionReachability.dormant(scenario, new DexContext(new ImmutableDexFile(input.getOpcodes(), metadataClasses)), model).contains(Signatures.of(dormant)));
    }
    @Test public void escapedCacheDisablesEveryDispatcherInItsOwner() {
        var entry = stringEntry(); String owner = entry.dispatcher().getDefiningClass();
        Method getter = dex.methods().get(Signatures.of(entry.get()));
        FieldReference cache = (FieldReference)((ReferenceInstruction)getter.getImplementation().getInstructions().iterator().next()).getReference();
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, cache));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method leak = new ImmutableMethod(owner, "leak", List.of(), "Ljava/util/Map;", 9, Set.of(), Set.of(), b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(methods::add); methods.add(leak);
            classes.add(new ImmutableClassDef(owner, cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        var modified = new ReflectionModel(new DexContext(new ImmutableDexFile(input.getOpcodes(), classes)));
        assertEquals(18, modified.dispatchers.size());
        assertTrue(modified.dispatchers.keySet().stream().noneMatch(s -> s.startsWith(owner + "->")));
    }
    @Test public void typedTargetInvocationIsOutsideAllHandlersAndFallbackRetainsOriginal() {
        var entry = model.dispatchers.values().stream().flatMap(m -> m.values().stream())
            .filter(e -> e.target().member() instanceof MethodReference m && m.getName().equals("shiftLong")).findFirst().orElseThrow();
        var resolved = new MemberResolver(dex, new LibraryTypes(List.of())).resolve(entry.target().member());
        var method = ReflectionCode.member("Lprobe/Calls;", "shift", entry, resolved);
        var g = new CodeGraph(method.getImplementation()); boolean target = false, fallback = false;
        for (int i = 0; i < g.size(); i++) if (g.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m) {
            if (Signatures.of(m).equals(Signatures.of((MethodReference)entry.target().member()))) { target = true; assertTrue(g.protection(i).isEmpty()); assertEquals(3, ((RegisterRangeInstruction)g.at(i)).getRegisterCount()); }
            if (Signatures.of(m).equals(Signatures.of(entry.dispatcher()))) fallback = true;
        }
        assertTrue(target); assertTrue(fallback);
    }
    @Test public void unknownIdsAreRetainedAndKnownStringsAreLinkedDespiteUnrelatedRollback() {
        var entry = stringEntry(); var b = new MethodImplementationBuilder(1);
        b.addInstruction(Edits.constant(0, entry.id()));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, entry.dispatcher()));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method caller = new ImmutableMethod("Lprobe/Caller;", "known", List.of(), ReflectionModel.OBJECT, 9, Set.of(), Set.of(), b.getMethodImplementation());
        b = new MethodImplementationBuilder(1); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method broken = new ImmutableMethod("Lprobe/Caller;", "broken", List.of(), "V", 9, Set.of(), Set.of(), b.getMethodImplementation());
        b = new MethodImplementationBuilder(1);
        b.addInstruction(Edits.constant(0, Integer.MIN_VALUE));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, entry.dispatcher()));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method unknown = new ImmutableMethod("Lprobe/Caller;", "unknown", List.of(), "V", 9, Set.of(), Set.of(), b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        classes.add(new ImmutableClassDef("Lprobe/Caller;", 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller, broken, unknown)));
        DexPass fail = new DexPass() { public String id() { return "test.fail"; } public PassResult run(MethodContext m) { if(m.original().getName().equals("broken")) throw new IllegalStateException("test"); return PassResult.unchanged(); } };
        var output = new DexEngine(List.of(new ReflectionTransformer(List.of(), true), fail), 4).transform(new ImmutableDexFile(input.getOpcodes(), classes));
        assertEquals(1, output.failedMethods());
        DexContext result = new DexContext(output.dex());
        Method changed = result.methods().get(Signatures.of(caller));
        MethodReference ref = null;
        for (var instruction : changed.getImplementation().getInstructions()) if (instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && m.getName().startsWith("np$resolved$")) ref = m;
        assertNotNull(ref);
        assertTrue(ref.getName().startsWith("np$resolved$")); assertNotNull(result.methods().get(Signatures.of(ref)));
        assertEquals(Signatures.of(entry.dispatcher()), Signatures.of(ReflectionModel.methodRef(new CodeGraph(result.methods().get(Signatures.of(unknown)).getImplementation()).at(1))));
        var second = new DexEngine(List.of(new ReflectionTransformer(List.of(), true)), 4).transform(output.dex());
        assertEquals(0, second.changedMethods()); assertEquals(0, second.dexEdits());
    }
}
