package me.naptila.deobfuscator;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.debug.LineNumber;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class BlockLayoutTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER = "Lsample/Test;";
    private static final ImmutableFieldReference TRACE = new ImmutableFieldReference(OWNER, "trace", "I");
    private static final int[] INPUTS = {Integer.MIN_VALUE, -1024, -1, 0, 1, 1024, Integer.MAX_VALUE};
    private List<ImmutableMethodParameter> parameters(String... types) {
        return Arrays.stream(types).map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList();
    }
    private DexFile dex(Method method) {
        Field trace = new ImmutableField(OWNER, "trace", "I", AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(0), Set.of(), Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28), List.of(new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", List.of(), "Layout.java", Set.of(), List.of(trace), List.of(method))));
    }
    private int normalize(MethodContext context) {
        int changes = 0;
        while (BlockLayout.run(context) != 0) { changes++; assertTrue("Block order did not stabilize", changes < 8); }
        return changes;
    }
    private Method serialize(Method method, String name) throws Exception {
        Path path = directory.getRoot().toPath().resolve(name+".dex"); DexFiles.write(path, dex(method));
        Method output = new DexContext(DexFiles.read(path)).findMethod(Signatures.of(method)).orElseThrow();
        assertEquals(0, BlockLayout.run(new MethodContext(output)));
        assertEquals(method.getImplementation().getRegisterCount(), output.getImplementation().getRegisterCount());
        return output;
    }
    private Method dag(int seed) {
        Random random = new Random(seed); int count = 12;
        var b = new MethodImplementationBuilder(4); Fixtures.integer(b, 0, 17); Fixtures.go(b,"block0");
        List<Integer> order = new ArrayList<>(); for (int i=0;i<count;i++) order.add(i); Collections.shuffle(order, random);
        List<Opcode> conditions = List.of(Opcode.IF_EQZ, Opcode.IF_NEZ, Opcode.IF_LTZ, Opcode.IF_LEZ, Opcode.IF_GTZ, Opcode.IF_GEZ);
        for (int block : order) {
            b.addLabel("block"+block);
            b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8,0,0,3));
            b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8,0,0,block+1));
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
            if (block==count-1) b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
            else {
                b.addInstruction(new BuilderInstruction22s(Opcode.XOR_INT_LIT16,1,3,block*257));
                int left=block+1+random.nextInt(count-block-1), right=block+1+random.nextInt(count-block-1);
                b.addInstruction(new BuilderInstruction21t(conditions.get(random.nextInt(conditions.size())),1,b.getLabel("block"+left)));
                Fixtures.go(b,"block"+right);
            }
        }
        return Fixtures.method("flow",parameters("I"),"I",b.getMethodImplementation());
    }
    @Test public void randomDagLayoutsPreserveResultsAndObservableWritesAndStabilize() throws Exception {
        int changed=0;
        for(int seed=0;seed<80;seed++) {
            Method input=dag(seed);var context=new MethodContext(input);changed+=normalize(context);
            Method output=serialize(context.finish(),"dag-"+seed);
            var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            for(int value:INPUTS) {
                assertEquals(before.run(Signatures.of(input),value),after.run(Signatures.of(output),value));
                assertEquals(before.field(Signatures.of(TRACE)),after.field(Signatures.of(TRACE)));
            }
        }
        assertTrue(changed>0);
    }
    private Method loop() {
        var b=new MethodImplementationBuilder(5);Fixtures.integer(b,0,0);Fixtures.integer(b,1,0);Fixtures.go(b,"guard");
        b.addLabel("exit");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("body");b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT,0,0,3));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8,1,1,1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,1,TRACE));Fixtures.go(b,"guard");
        b.addLabel("guard");b.addInstruction(new BuilderInstruction22t(Opcode.IF_LT,1,4,b.getLabel("body")));Fixtures.go(b,"exit");
        return Fixtures.method("flow",parameters("I","I"),"I",b.getMethodImplementation());
    }
    @Test public void loopsKeepBackedgesAndExecuteEffectsOncePerIteration() throws Exception {
        Method input=loop();var context=new MethodContext(input);assertTrue(normalize(context)>0);
        Method output=serialize(context.finish(),"loop");
        for(int value:INPUTS)for(int rounds=0;rounds<=8;rounds++) {
            var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            assertEquals(before.run(Signatures.of(input),value,rounds),after.run(Signatures.of(output),value,rounds));
            assertEquals(before.field(Signatures.of(TRACE)),after.field(Signatures.of(TRACE)));
        }
    }
    @Test public void referenceAndNullIdentitySurviveBlockPlacement() throws Exception {
        var b=new MethodImplementationBuilder(5);Fixtures.go(b,"guard");
        b.addLabel("use");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,3));
        b.addLabel("fallback");Fixtures.string(b,0,"fallback");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,0));
        b.addLabel("guard");b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,4,b.getLabel("use")));Fixtures.go(b,"fallback");
        Method input=Fixtures.method("flow",parameters("Ljava/lang/String;","I"),"Ljava/lang/String;",b.getMethodImplementation());
        var context=new MethodContext(input);assertTrue(normalize(context)>0);Method output=serialize(context.finish(),"references");
        var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
        for(String text:new String[]{null,"",new String("对象🙂")})for(int selector:INPUTS) {
            Object expected=before.run(Signatures.of(input),text,selector),actual=after.run(Signatures.of(output),text,selector);
            if(selector==0)assertSame(text,actual);else assertEquals(expected,actual);
        }
    }
    private Method throwing(boolean protect,boolean lines,boolean locals) {
        var b=new MethodImplementationBuilder(4);
        if(lines)b.addLineNumber(7);
        Fixtures.integer(b,0,11);b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));Fixtures.go(b,"call");
        b.addLabel("done");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
        b.addLabel("call");Fixtures.integer(b,0,22);b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
        if(locals)b.addStartLocal(0,new ImmutableStringReference("saved"),new ImmutableTypeReference("I"),null);
        b.addLabel("start");b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL,1,3,0,0,0,0,Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT,1));b.addLabel("end");
        Fixtures.integer(b,0,33);b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));Fixtures.go(b,"done");
        if(protect) {
            b.addLabel("handler");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,1));
            Fixtures.integer(b,1,-1);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
            b.addCatch("Ljava/lang/Exception;",b.getLabel("start"),b.getLabel("end"),b.getLabel("handler"));
        }
        return Fixtures.method("flow",parameters("Ljava/lang/String;"),"I",b.getMethodImplementation());
    }
    @Test public void uncaughtExceptionsKeepEarlierSideEffectsAndSuppressLaterOnes() throws Exception {
        Method input=throwing(false,false,false);var context=new MethodContext(input);assertTrue(normalize(context)>0);
        Method output=serialize(context.finish(),"throwing");
        var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
        assertThrows(NullPointerException.class,()->before.run(Signatures.of(input),(Object)null));
        assertThrows(NullPointerException.class,()->after.run(Signatures.of(output),(Object)null));
        assertEquals(22,before.field(Signatures.of(TRACE)));assertEquals(22,after.field(Signatures.of(TRACE)));
        for(String text:List.of("","abc","测试🙂")) {
            assertEquals(before.run(Signatures.of(input),text),after.run(Signatures.of(output),text));
            assertEquals(33,after.field(Signatures.of(TRACE)));
        }
    }
    @Test public void methodsWithDebugMetadataKeepTheirOriginalLayout() {
        for(Method input:List.of(throwing(false,true,false),throwing(false,false,true))) {
            var context=new MethodContext(input);assertEquals(0,BlockLayout.run(context));
            var output=context.finish();
            assertEquals(input.getImplementation().getTryBlocks().size(),output.getImplementation().getTryBlocks().size());
            List<String> before=new ArrayList<>(),after=new ArrayList<>();
            for(var d:input.getImplementation().getDebugItems())before.add(d.getDebugItemType()+":"+d.getCodeAddress()+":"+(d instanceof LineNumber l?l.getLineNumber():"local"));
            for(var d:output.getImplementation().getDebugItems())after.add(d.getDebugItemType()+":"+d.getCodeAddress()+":"+(d instanceof LineNumber l?l.getLineNumber():"local"));
            assertEquals(before,after);
        }
    }
    @Test public void methodsWithSwitchesOrArrayPayloadsAreRetained() {
        assertEquals(0,BlockLayout.run(new MethodContext(Fixtures.flattened(false,false,false))));
        var b=new MethodImplementationBuilder(1);Fixtures.integer(b,0,7);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addInstruction(new BuilderArrayPayload(1,List.of(1,2,3)));
        assertEquals(0,BlockLayout.run(new MethodContext(Fixtures.method("flow",List.of(),"I",b.getMethodImplementation()))));
    }
    @Test public void postLayoutDeadCleanupKeepsPotentiallyThrowingDefinitions() {
        var b=new MethodImplementationBuilder(3);Fixtures.string(b,0,"keep linkage and allocation behavior");
        Fixtures.integer(b,1,7);Fixtures.integer(b,2,9);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,2));
        var context=new MethodContext(Fixtures.method("flow",List.of(),"I",b.getMethodImplementation()));
        assertEquals(1, DeadAssignments.removeNonThrowing(context));
        var graph=context.graph();assertEquals(Opcode.CONST_STRING,graph.at(0).getOpcode());
        assertEquals(9,new NpNumericInterpreter(dex(context.finish())).run("Lsample/Test;->flow()I"));
    }
    @Test public void appliesAfterCleanupWithDirectNpEvidence() {
        Method method=dag(21);var code=new MutableMethodImplementation(method.getImplementation());
        code.addInstruction(0,new BuilderInstruction21c(Opcode.CONST_STRING,2,new ImmutableStringReference("layout")));
        code.addInstruction(1,new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,2,0,0,0,0,Fixtures.NP_HASH));
        Method input=new ImmutableMethod(OWNER,method.getName(),method.getParameters(),method.getReturnType(),method.getAccessFlags(),Set.of(),Set.of(),code);
        var classes=new ArrayList<ClassDef>(Fixtures.npDex().getClasses());classes.removeIf(c->c.getType().equals(OWNER));classes.addAll(dex(input).getClasses());
        var source=new ImmutableDexFile(Opcodes.forApi(28),classes);
        var result=new Deobfuscator(TransformerRegistry.discover()).transform(source,RunConfiguration.defaults().transformers(),20);
        assertEquals(0,result.failedMethods());assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        assertTrue(result.methods().stream().flatMap(m->m.steps().stream()).flatMap(s->s.result().notes().stream()).anyMatch(s->s.startsWith("NP method blocks reordered:")));
        assertFalse(result.methods().stream().flatMap(m->m.steps().stream()).flatMap(s->s.result().notes().stream()).anyMatch(s->s.contains("normalization limit")));
        Method output=new DexContext(result.dex()).findMethod(Signatures.of(input)).orElseThrow();
        assertEquals(0,BlockLayout.run(new MethodContext(output)));
    }
}
