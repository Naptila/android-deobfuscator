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

public class ConditionalLiteralsTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER="Lsample/Test;";
    private static final ImmutableFieldReference TRACE=new ImmutableFieldReference(OWNER,"trace","I");
    private static final ImmutableMethodReference EFFECT=new ImmutableMethodReference(OWNER,"effect",List.of("I"),"I");
    private static final int[] VALUES={Integer.MIN_VALUE,-32768,-1,0,1,32767,Integer.MAX_VALUE};
    private List<ImmutableMethodParameter> params(String... types) {
        return Arrays.stream(types).map(t->new ImmutableMethodParameter(t,Set.of(),null)).toList();
    }
    private void literal(MethodImplementationBuilder b,Opcode op,int value) {
        b.addInstruction(switch(op) {
            case CONST_4 -> new BuilderInstruction11n(op,0,value);
            case CONST_16 -> new BuilderInstruction21s(op,0,value);
            case CONST_HIGH16 -> new BuilderInstruction21ih(op,0,value);
            default -> new BuilderInstruction31i(op,0,value);
        });
    }
    private boolean two(Opcode op) { return op==Opcode.IF_EQ||op==Opcode.IF_NE||op==Opcode.IF_LT||op==Opcode.IF_LE||op==Opcode.IF_GT||op==Opcode.IF_GE; }
    private Method fixture(Opcode op,int value,Opcode condition,boolean taken,String hazard) {
        var b=new MethodImplementationBuilder(10);
        Fixtures.integer(b,2,0);b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,2,TRACE));
        b.addLineNumber(10);literal(b,op,value);
        if(hazard.equals("local"))b.addStartLocal(0,new ImmutableStringReference("id"),new ImmutableTypeReference("I"),null);
        if(hazard.equals("write"))b.addInstruction(new BuilderInstruction12x(Opcode.MOVE,0,8));
        if(hazard.equals("read"))b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
        if(hazard.equals("loop")){b.addLabel("loop");Fixtures.go(b,"loop");}
        if(hazard.equals("budget"))for(int i=0;i<70;i++)b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        if(hazard.equals("constructor")) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE,2,new ImmutableTypeReference("Ljava/lang/Object;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT,1,2,0,0,0,0,new ImmutableMethodReference("Ljava/lang/Object;","<init>",List.of(),"V")));
        }
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,9,0,0,0,0,EFFECT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT,1));
        b.addLineNumber(20);
        b.addInstruction(two(condition)?new BuilderInstruction22t(condition,9,8,b.getLabel("taken")):new BuilderInstruction21t(condition,9,b.getLabel("taken")));
        if(taken&&!hazard.equals("both"))b.addInstruction(new BuilderInstruction12x(Opcode.MOVE,0,8));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("taken");b.addLineNumber(30);
        if(!taken&&!hazard.equals("both"))b.addInstruction(new BuilderInstruction12x(Opcode.MOVE,0,8));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        return Fixtures.method("flow",params("I","I"),"I",b.getMethodImplementation());
    }
    private DexFile dex(Method method) {
        var b=new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET,0,TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8,0,0,1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,2));
        Method effect=Fixtures.method("effect",params("I"),"I",b.getMethodImplementation());
        Field field=new ImmutableField(OWNER,"trace","I",AccessFlags.STATIC.getValue(),new ImmutableIntEncodedValue(0),Set.of(),Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28),List.of(new ImmutableClassDef(OWNER,1,"Ljava/lang/Object;",List.of(),null,Set.of(),List.of(field),List.of(method,effect))));
    }
    private Method serialize(Method method,String name)throws Exception {
        Path file=directory.getRoot().toPath().resolve(name+".dex");DexFiles.write(file,dex(method));
        return new DexContext(DexFiles.read(file)).findMethod(Signatures.of(method)).orElseThrow();
    }
    @Test public void allLiteralEncodingsConditionsAndEdgesKeepValuesAndCallCounts()throws Exception {
        List<Opcode> ops=List.of(Opcode.CONST_4,Opcode.CONST_16,Opcode.CONST,Opcode.CONST_HIGH16);
        int[][] values={{-8,0,7},{-32768,32767},{Integer.MIN_VALUE,Integer.MAX_VALUE},{Integer.MIN_VALUE,0x7fff0000}};
        int index=0;
        for(int k=0;k<ops.size();k++)for(int value:values[k])
            for(Opcode condition:List.of(Opcode.IF_EQ,Opcode.IF_NE,Opcode.IF_LT,Opcode.IF_LE,Opcode.IF_GT,Opcode.IF_GE,Opcode.IF_EQZ,Opcode.IF_NEZ,Opcode.IF_LTZ,Opcode.IF_LEZ,Opcode.IF_GTZ,Opcode.IF_GEZ))
                for(boolean taken:List.of(false,true)) {
                    Method input=fixture(ops.get(k),value,condition,taken,"");var context=new MethodContext(input);
                    assertEquals(1, ConditionalCopies.runLiterals(context));assertEquals(0,ConditionalCopies.runLiterals(context));
                    Method output=serialize(context.finish(),"literal-"+index++);
                    var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
                    for(int a:VALUES)for(int b:VALUES) {
                        assertEquals(before.run(Signatures.of(input),a,b),after.run(Signatures.of(output),a,b));
                        assertEquals(1,before.field(Signatures.of(TRACE)));assertEquals(1,after.field(Signatures.of(TRACE)));
                    }
                    assertEquals(0,ConditionalCopies.runLiterals(new MethodContext(output)));
                }
    }
    @Test public void zeroKeepsNullReferenceComparisonAndObjectIdentity()throws Exception {
        var b=new MethodImplementationBuilder(4);Fixtures.integer(b,0,0);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,3,b.getLabel("use")));
        Fixtures.integer(b,1,-1);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
        b.addLabel("use");b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ,2,0,b.getLabel("null")));
        Fixtures.integer(b,1,0);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
        b.addLabel("null");Fixtures.integer(b,1,1);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
        Method input=Fixtures.method("flow",params("Ljava/lang/Object;","I"),"I",b.getMethodImplementation());
        var context=new MethodContext(input);assertEquals(1,ConditionalCopies.runLiterals(context));Method output=serialize(context.finish(),"null");
        var after=new NpNumericInterpreter(dex(output));
        for(Object value:new Object[]{null,new String(""),new String("中文")})for(int selector:VALUES)
            assertEquals(selector!=0?-1:value==null?1:0,after.run(Signatures.of(output),value,selector));
    }
    private Method exceptional(boolean protect) {
        var b=new MethodImplementationBuilder(6);Fixtures.integer(b,0,73);Fixtures.integer(b,2,0);
        b.addLabel("start");b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE,1,4,2));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,5,b.getLabel("use")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE,0,3));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("use");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));b.addLabel("end");
        if(protect) {
            b.addLabel("handler");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,1));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
            b.addCatch("Ljava/lang/Exception;",b.getLabel("start"),b.getLabel("end"),b.getLabel("handler"));
        }
        return Fixtures.method("flow",params("I","[B","I"),"I",b.getMethodImplementation());
    }
    @Test public void preservesCaughtAndUncaughtFailuresBeforeTheConditional()throws Exception {
        for(boolean protect:List.of(false,true)) {
            Method input=exceptional(protect);var context=new MethodContext(input);assertEquals(protect?0:1,ConditionalCopies.runLiterals(context));
            Method output=serialize(context.finish(),"protected-"+protect);var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            for(int selector:VALUES) {
                assertEquals(before.run(Signatures.of(input),41,new byte[]{1},selector),after.run(Signatures.of(output),41,new byte[]{1},selector));
                if(protect)for(Object array:new Object[]{null,new byte[0]})assertEquals(73,after.run(Signatures.of(output),41,array,selector));
                else {
                    assertThrows(NullPointerException.class,()->after.run(Signatures.of(output),41,null,selector));
                    assertThrows(ArrayIndexOutOfBoundsException.class,()->after.run(Signatures.of(output),41,new byte[0],selector));
                }
            }
        }
    }
    @Test public void retainsObservedAssignmentsLocalsCyclesAndThrowingOrWideConstants() {
        for(String hazard:List.of("write","read","both","local","loop","budget","constructor"))
            assertEquals(hazard,0,ConditionalCopies.runLiterals(new MethodContext(fixture(Opcode.CONST,123,Opcode.IF_EQZ,true,hazard))));
        for(boolean wide:List.of(false,true)) {
            var b=new MethodImplementationBuilder(4);
            b.addInstruction(wide?new BuilderInstruction51l(Opcode.CONST_WIDE,0,123):new BuilderInstruction21c(Opcode.CONST_STRING,0,new ImmutableStringReference("keep")));
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,3,b.getLabel("use")));
            b.addInstruction(wide?new BuilderInstruction51l(Opcode.CONST_WIDE,0,456):new BuilderInstruction21c(Opcode.CONST_STRING,0,new ImmutableStringReference("other")));
            b.addLabel("use");b.addInstruction(new BuilderInstruction11x(wide?Opcode.RETURN_WIDE:Opcode.RETURN_OBJECT,0));
            assertEquals(0,ConditionalCopies.runLiterals(new MethodContext(Fixtures.method("flow",params("I"),wide?"J":"Ljava/lang/String;",b.getMethodImplementation()))));
        }
    }
    @Test public void preservesHighRegisterEncodingAndLineMarkersAfterSerialization()throws Exception {
        var b=new MethodImplementationBuilder(300);b.addLineNumber(10);b.addInstruction(new BuilderInstruction21ih(Opcode.CONST_HIGH16,200,0x12340000));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16,9,299));b.addLineNumber(20);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,9,b.getLabel("use")));
        Fixtures.integer(b,0,-1);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("use");b.addLineNumber(30);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,200));
        Method input=Fixtures.method("flow",params("I"),"I",b.getMethodImplementation());var context=new MethodContext(input);
        assertEquals(1,ConditionalCopies.runLiterals(context));Method output=serialize(context.finish(),"high");
        List<Integer> lines=new ArrayList<>();for(var d:output.getImplementation().getDebugItems())if(d instanceof LineNumber l)lines.add(l.getLineNumber());
        assertEquals(List.of(10,20,30),lines);assertEquals(300,output.getImplementation().getRegisterCount());
        var after=new NpNumericInterpreter(dex(output));for(int selector:VALUES)assertEquals(selector==0?0x12340000:-1,after.run(Signatures.of(output),selector));
    }
    @Test public void npPipelineUsesTheLiteralProofAndConvergesWithoutFurtherEdits() {
        Method original=fixture(Opcode.CONST,123,Opcode.IF_EQZ,true,"");var code=new MutableMethodImplementation(original.getImplementation());
        code.addInstruction(0,new BuilderInstruction21c(Opcode.CONST_STRING,2,new ImmutableStringReference("literal")));
        code.addInstruction(1,new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,2,0,0,0,0,Fixtures.NP_HASH));
        Method input=new ImmutableMethod(OWNER,original.getName(),original.getParameters(),original.getReturnType(),original.getAccessFlags(),Set.of(),Set.of(),code);
        var classes=new ArrayList<ClassDef>(Fixtures.npDex().getClasses());classes.removeIf(c->c.getType().equals(OWNER));classes.addAll(dex(input).getClasses());
        var engine=new Deobfuscator(TransformerRegistry.discover());var result=engine.transform(new ImmutableDexFile(Opcodes.forApi(28),classes),RunConfiguration.defaults().transformers(),20);
        assertEquals(0,result.failedMethods());assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        assertTrue(result.methods().stream().flatMap(m->m.steps().stream()).flatMap(s->s.result().notes().stream()).anyMatch(s->s.startsWith("integer constants delayed to live conditional edges:")));
        assertEquals(0,engine.transform(result.dex(),RunConfiguration.defaults().transformers(),20).changedMethods());
    }
}
