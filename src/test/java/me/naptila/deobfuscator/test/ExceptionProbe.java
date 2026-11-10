package me.naptila.deobfuscator.test;

import java.lang.reflect.InvocationTargetException;

/** Runs independently on ART, against either the original or transformed regression DEX. */
public final class ExceptionProbe {
    private static String trace;
    private static int mode;
    public static int raise(int input) {
        trace += "R"; mode = input;
        switch (input) {
            case 1: case 4: throw new ArithmeticException("arithmetic");
            case 2: throw new IllegalArgumentException("runtime");
            case 3: throw new AssertionError("error");
            default: return 7;
        }
    }
    public static void mark(int label) {
        trace += label == 1 ? "C" : "F";
        if (label == 1 && mode == 4) throw new IllegalStateException("catch failed");
    }
    private static String run(Class<?> target, String name, int input) throws Exception {
        trace = ""; mode = input;
        String result;
        try { result = String.valueOf(target.getMethod(name, int.class).invoke(null, input)); }
        catch (InvocationTargetException e) { result = "throws:" + e.getCause().getClass().getSimpleName(); }
        return result + "|" + trace;
    }
    public static void main(String[] args) throws Exception {
        Class<?> target = Class.forName("sample.ExceptionRegression");
        String[][] cases = {
            {"destinationOnThrow", "-1", "-42|"}, {"destinationOnThrow", "0", "42|"}, {"destinationOnThrow", "2", "21|"},
            {"wideOnThrow", "-1", "-37|"}, {"wideOnThrow", "0", "-9223372036854775801|"}, {"wideOnThrow", "2", "18|"},
            {"orderedCatch", "0", "7|RF"}, {"orderedCatch", "1", "11|RF"}, {"orderedCatch", "2", "22|RF"}, {"orderedCatch", "3", "33|RF"},
            {"nestedFinally", "0", "7|RF"}, {"nestedFinally", "1", "101|RCF"},
            {"nestedFinally", "2", "throws:IllegalArgumentException|RF"}, {"nestedFinally", "3", "throws:AssertionError|RF"},
            {"nestedFinally", "4", "throws:IllegalStateException|RCF"},
            {"deadTry", "0", "8|"}, {"deadTry", "3", "8|"},
            {"sharedSame", "-1", "2|"}, {"sharedSame", "1", "1|"},
            {"sharedCross", "-1", "2|"}, {"sharedCross", "1", "1|"}, {"protectedNullHash", "0", "77|"}
        };
        int failed = 0;
        System.out.println("id\texpected\tactual\tstatus");
        for (String[] c : cases) {
            String actual = run(target, c[0], Integer.parseInt(c[1]));
            boolean passed = actual.equals(c[2]);
            System.out.println(c[0] + "." + c[1] + "\t" + c[2] + "\t" + actual + "\t" + (passed ? "PASS" : "FAIL"));
            if (!passed) failed++;
        }
        System.out.println("PASS " + (cases.length - failed) + "/" + cases.length);
        if (failed != 0) throw new AssertionError("Exception regressions failed: " + failed);
    }
}
