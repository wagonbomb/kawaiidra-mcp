import java.io.PrintWriter;
import java.util.List;
import javax.swing.SwingUtilities;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.GhidraRun;
import ghidra.app.script.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Test harness: boot the Ghidra GUI on a project, open the Debugger tool on a
 * program, and run a (Jython) script inside that tool — used to start the
 * ghidra_bridge server where the debugger services exist.
 * args: <project .gpr> <program path in project> <script file>
 */
public class KawaiiDebugHarness implements GhidraLaunchable {
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		new GhidraRun().launch(layout, new String[] { args[0] });
		Project project = null;
		for (int i = 0; i < 480 && (project = AppInfo.getActiveProject()) == null; i++) {
			Thread.sleep(250);
		}
		if (project == null) {
			fail("project did not open");
		}
		log("project open: " + project.getName());
		DomainFile df = project.getProjectData().getFile("/" + args[1].replaceFirst("^/", ""));
		if (df == null) {
			fail("program not in project: " + args[1]);
		}
		final Project proj = project;
		final PluginTool[] tool = new PluginTool[1];
		SwingUtilities.invokeAndWait(() -> tool[0] = proj.getToolServices().launchTool("Debugger", List.of(df)));
		if (tool[0] == null) {
			fail("Debugger tool did not launch");
		}
		log("tool: " + tool[0].getName());
		ProgramManager pm = tool[0].getService(ProgramManager.class);
		Program program = null;
		for (int i = 0; i < 480 && (program = pm.getCurrentProgram()) == null; i++) {
			Thread.sleep(250);
		}
		if (program == null) {
			fail("program did not open in Debugger tool");
		}
		log("program: " + program.getName());
		ResourceFile script = new ResourceFile(args[2]);
		PrintWriter out = new PrintWriter(System.out, true);
		GhidraScript s = GhidraScriptUtil.getProvider(script).getScriptInstance(script, out);
		GhidraState state = new GhidraState(tool[0], proj, program,
			new ProgramLocation(program, program.getMinAddress()), null, null);
		s.execute(state, new ScriptControls(out, out, TaskMonitor.DUMMY));
		log("bridge script started; GUI stays up");
	}

	private static void log(String m) {
		System.out.println("HARNESS: " + m);
	}

	private static void fail(String m) {
		System.out.println("HARNESS FAIL: " + m);
		System.exit(2);
	}
}
