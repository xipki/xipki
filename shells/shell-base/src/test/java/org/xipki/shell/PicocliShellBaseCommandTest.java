// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.junit.Assert;
import org.junit.Test;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;
import java.util.stream.Collectors;

/**
 * Tests for core shell command helpers.
 *
 * @author Lijun Liao (xipki)
 */
public class PicocliShellBaseCommandTest {

  @Test
  public void testSaveVerboseOverwriteYes() throws Exception {
    Path dir = Files.createTempDirectory("xipki-save-yes-");
    Path target = dir.resolve("a.txt");
    Files.write(target, "old".getBytes(StandardCharsets.UTF_8));

    TestSaveCommand cmd = new TestSaveCommand("yes");
    cmd.saveVerbose("saved to file", target, "new".getBytes(StandardCharsets.UTF_8));

    Assert.assertEquals("new", Files.readString(target));
    Assert.assertTrue(cmd.output().contains("saved to file " + target));
  }

  @Test
  public void testSaveVerboseNoThenNewPathAfterEmptyPrompts() throws Exception {
    Path dir = Files.createTempDirectory("xipki-save-no-");
    Path target = dir.resolve("a.txt");
    Path alt = dir.resolve("b.txt");
    Files.write(target, "old".getBytes(StandardCharsets.UTF_8));

    TestSaveCommand cmd = new TestSaveCommand("no", "", "", alt.toString());
    cmd.saveVerbose("saved to file", target, "new".getBytes(StandardCharsets.UTF_8));

    Assert.assertEquals("old", Files.readString(target));
    Assert.assertEquals("new", Files.readString(alt));
    Assert.assertTrue(cmd.output().contains("saved to file " + alt));
  }

  @Test
  public void testSaveVerboseCtrlCUsesTmpFile() throws Exception {
    Path dir = Files.createTempDirectory("xipki-save-interrupt-");
    Path target = dir.resolve("a.txt");
    Files.write(target, "old".getBytes(StandardCharsets.UTF_8));

    TestSaveCommand cmd = new TestSaveCommand("no");
    cmd.failAfterPrompts();
    cmd.saveVerbose("saved to file", target, "new".getBytes(StandardCharsets.UTF_8));

    Assert.assertTrue(cmd.output().contains("saved to file tmp-"));
  }

  @Test
  public void testSourceReturnResumesParentScript() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-return-parent-");
    Path child = dir.resolve("b.script");
    Files.writeString(child, String.join(System.lineSeparator(),
        "echo commands-b1",
        "return",
        "echo commands-b2") + System.lineSeparator());

    Path parent = dir.resolve("a.script");
    Files.writeString(parent, String.join(System.lineSeparator(),
        "echo commands-a1",
        "source " + child.getFileName(),
        "echo commands-a2") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(0, shell.executeScript(parent.toString()));
    Assert.assertEquals(List.of("commands-a1", "commands-b1", "commands-a2"), shell.outputLines());
  }

  @Test
  public void testSourceCommandReturnDoesNotBreakFollowingCommands() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-command-return-");
    Path child = dir.resolve("b.script");
    Files.writeString(child, String.join(System.lineSeparator(),
        "echo commands-b1",
        "return",
        "echo commands-b2") + System.lineSeparator());

    Path parent = dir.resolve("a.script");
    Files.writeString(parent, String.join(System.lineSeparator(),
        "echo commands-a1",
        "source " + child.getFileName(),
        "echo commands-a2") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(0, shell.executeLine("source " + parent));
    Assert.assertEquals("", shell.errorOutput());
    Assert.assertEquals(0, shell.executeLine("echo after-source"));
    Assert.assertEquals(List.of("commands-a1", "commands-b1", "commands-a2", "after-source"),
        shell.outputLines());
  }

  @Test
  public void testReturnEndsTopLevelScript() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-return-top-");
    Path script = dir.resolve("a.script");
    Files.writeString(script, String.join(System.lineSeparator(),
        "echo one",
        "return",
        "echo two") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(0, shell.executeScript(script.toString()));
    Assert.assertEquals(List.of("one"), shell.outputLines());
  }

  @Test
  public void testReturnInsideIfEndsCurrentScript() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-return-if-");
    Path script = dir.resolve("if-return.script");
    Files.writeString(script, String.join(System.lineSeparator(),
        "if a eq a",
        "  echo before-return",
        "  return",
        "fi",
        "echo after-if") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(0, shell.executeScript(script.toString()));
    Assert.assertEquals(List.of("before-return"), shell.outputLines());
  }

  @Test
  public void testReturnInsideForEndsCurrentScript() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-return-for-");
    Path script = dir.resolve("for-return.script");
    Files.writeString(script, String.join(System.lineSeparator(),
        "for i in a b",
        "  echo ${i}",
        "  return",
        "done",
        "echo after-for") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(0, shell.executeScript(script.toString()));
    Assert.assertEquals(List.of("a"), shell.outputLines());
  }

  @Test
  public void testExitStillStopsShellAndReturnOutsideScriptFailsCleanly() throws Exception {
    TestShell shell = new TestShell();

    int returnCode = shell.commandLine().execute("return");
    Assert.assertNotEquals(0, returnCode);
    Assert.assertTrue(shell.errorOutput().contains(
        "return can only be used while executing a script"));
    Assert.assertTrue(isRunning(shell));

    int exitCode = shell.commandLine().execute("exit");
    Assert.assertEquals(0, exitCode);
    Assert.assertFalse(isRunning(shell));
  }

  @Test
  public void testExceptionCommandThrowsRequestedMessage() {
    TestShell shell = new TestShell();

    int rc = shell.executeLine("exception boom");

    Assert.assertEquals(1, rc);
    Assert.assertTrue(shell.errorOutput().contains("boom"));
  }

  @Test
  public void testSourceCommandFailureDoesNotPrintNestedStackTrace() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-command-failure-");
    Path script = dir.resolve("failure.script");
    Files.writeString(script, String.join(System.lineSeparator(),
        "echo before",
        "exception boom",
        "echo after") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(1, shell.executeLine("source " + script));
    Assert.assertEquals(List.of("before"), shell.outputLines());
    Assert.assertTrue(shell.errorOutput().contains("boom"));
    Assert.assertFalse(shell.errorOutput().contains("ScriptCommandFailureException"));
    Assert.assertEquals(0, shell.executeLine("echo recovered"));
    Assert.assertEquals(List.of("before", "recovered"), shell.outputLines());
  }

  @Test
  public void testQuitStillStopsShellAfterSourceFailure() throws Exception {
    Path dir = Files.createTempDirectory("xipki-interactive-source-failure-");
    Path script = dir.resolve("failure.script");
    Files.writeString(script, String.join(System.lineSeparator(),
        "echo before",
        "exception boom",
        "echo after") + System.lineSeparator());

    TestShell shell = new TestShell();
    Assert.assertEquals(1, shell.executeLine("source " + script));
    Assert.assertEquals(0, shell.executeLine("quit"));

    Assert.assertFalse(isRunning(shell));
    Assert.assertEquals(List.of("before"), shell.outputLines());
    Assert.assertTrue(shell.errorOutput().contains("boom"));
  }

  @Test
  public void testSourceCommandReturnsNonZeroInsteadOfThrowing() throws Exception {
    Path dir = Files.createTempDirectory("xipki-source-command-rc-");
    Path script = dir.resolve("failure.script");
    Files.writeString(script, "exception boom" + System.lineSeparator());

    TestShell shell = new TestShell();

    Assert.assertEquals(1, shell.commandLine().execute("source", script.toString()));
    Assert.assertTrue(shell.errorOutput().contains("boom"));
  }

  private static boolean isRunning(PicocliShell shell) throws Exception {
    Field field = PicocliShell.class.getDeclaredField("running");
    field.setAccessible(true);
    return field.getBoolean(shell);
  }

  private static class TestSaveCommand extends ShellBaseCommand {

    private final Queue<String> answers = new ArrayDeque<>();

    private final StringWriter output = new StringWriter();

    private boolean failAfterPrompts;

    TestSaveCommand(String... prompts) {
      for (String prompt : prompts) {
        answers.add(prompt);
      }

      CommandLine commandLine = new CommandLine(new NoopCommand());
      commandLine.setOut(new PrintWriter(output, true));
      this.spec = commandLine.getCommandSpec();
    }

    void failAfterPrompts() {
      this.failAfterPrompts = true;
    }

    String output() {
      return output.toString();
    }

    @Override
    protected String readPrompt(String prompt) throws java.io.IOException {
      if (answers.isEmpty() && failAfterPrompts) {
        throw new java.io.IOException("interrupted");
      }

      return answers.isEmpty() ? "" : answers.remove();
    }

    @Override
    public void run() {
    }
  }

  @Command(name = "noop")
  private static class NoopCommand implements Runnable {

    @Override
    public void run() {
    }
  }

  @Command(name = "root")
  private static class EmptyRootCommand implements Runnable {

    @Override
    public void run() {
    }
  }

  private static class TestShell extends PicocliShell {

    private final StringWriter output;

    private final StringWriter error;

    TestShell() {
      this(new StringWriter(), new StringWriter());
    }

    private TestShell(StringWriter output, StringWriter error) {
      super("test> ", new EmptyRootCommand(), new PrintWriter(output, true));
      this.output = output;
      this.error = error;
      commandLine().setErr(new PrintWriter(error, true));
    }

    List<String> outputLines() {
      return output.toString().lines().filter(line -> !line.isBlank()).collect(Collectors.toList());
    }

    String errorOutput() {
      return error.toString();
    }
  }

}
