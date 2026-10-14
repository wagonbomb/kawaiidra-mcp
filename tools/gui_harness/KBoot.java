/** Adds the harness jar to GhidraClassLoader, then runs ghidra.Ghidra.main. args[0] = harness jar. */
public class KBoot {
	public static void main(String[] args) throws Exception {
		ClassLoader sys = ClassLoader.getSystemClassLoader();
		sys.getClass().getMethod("addPath", String.class).invoke(sys, args[0]);
		String[] rest = java.util.Arrays.copyOfRange(args, 1, args.length);
		Class.forName("ghidra.Ghidra", true, sys).getMethod("main", String[].class).invoke(null, (Object) rest);
	}
}
