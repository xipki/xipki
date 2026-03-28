// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.LineReader;
import org.jline.reader.ParsedLine;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Parameters;

import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Picocli Shell.
 *
 * @author Lijun Liao (xipki)
 */
public class PicocliShell {

  private static final Logger LOG = LoggerFactory.getLogger(PicocliShell.class);

  private static final String EMPTY_TOKEN_SENTINEL = "__PSHELL_EMPTY__";

  private static final ThreadLocal<LineReader> ACTIVE_LINE_READER = new ThreadLocal<>();

  private static final ThreadLocal<Terminal> ACTIVE_TERMINAL = new ThreadLocal<>();

  private static final ScriptReturnSignal SCRIPT_RETURN_SIGNAL = new ScriptReturnSignal();

  private final String prompt;

  private final PrintWriter out;

  private final DefaultParser parser = new DefaultParser().escapeChars(new char[0]);

  private final CommandLine commandLine;

  private final ShellHelpSupport helpSupport;

  private final ShellCommandExecutor commandExecutor;

  private final InteractiveShellRunner interactiveRunner;

  private final SourceCommand sourceAction;

  private final ShellScriptContext interactiveContext =
      new ShellScriptContext(List.of(), Paths.get("."));

  private boolean running = true;

  /**
   * Creates a reusable shell runner for the given root command.
   *
   * @param prompt interactive prompt text
   * @param rootCommand root picocli command object
   * @param out output writer used by the shell
   */
  public PicocliShell(String prompt, Object rootCommand, PrintWriter out) {
    this.prompt = prompt;
    this.out = out;
    this.commandLine = new CommandLine(rootCommand);
    this.helpSupport = new ShellHelpSupport(this);
    this.commandExecutor = new ShellCommandExecutor(this);
    this.interactiveRunner = new InteractiveShellRunner(this);
    this.sourceAction = new SourceCommand(this);
    this.commandLine.addSubcommand("help", new ShellHelpCommand(this));
    this.commandLine.addSubcommand("source", sourceAction);
    this.commandLine.getSubcommands().get("source").getCommandSpec().parser()
        .unmatchedOptionsArePositionalParams(true);
    this.commandLine.addSubcommand("set", new SetCommand(this));
    this.commandLine.addSubcommand("unset", new UnsetCommand(this));
    this.commandLine.addSubcommand("echo", new EchoCommand(this));
    this.commandLine.addSubcommand("exception", new ExceptionCommand());
    this.commandLine.addSubcommand("less", new LessCommand(this));
    this.commandLine.addSubcommand("sleep", new SleepCommand(this));
    this.commandLine.addSubcommand("clear", new ClearCommand(this));
    this.commandLine.addSubcommand("return", new ReturnCommand(this));
    this.commandLine.addSubcommand("exit", new ExitCommand(this));
    this.commandLine.addSubcommand("quit", new ExitCommand(this));
    this.commandLine.setParameterExceptionHandler(this::handleParameterException);
    this.commandLine.setExecutionExceptionHandler(
        (ex, cmd, parseResult) -> handleExecutionException(ex, cmd));
    helpSupport.enableDefaultValueDisplay(this.commandLine.getCommandSpec());
  }

  /**
   * Runs the given root command in interactive mode with no startup arguments.
   *
   * @param prompt interactive prompt text
   * @param rootCommand root picocli command object
   * @throws Exception on shell startup failure
   */
  public static void run(String prompt, Object rootCommand) throws Exception {
    run(prompt, rootCommand, new String[0]);
  }

  /**
   * Runs the given root command either interactively or in one-shot mode.
   *
   * @param prompt interactive prompt text
   * @param rootCommand root picocli command object
   * @param args startup arguments to execute
   * @return process-style exit code
   * @throws Exception on shell startup failure
   */
  public static int run(String prompt, Object rootCommand, String[] args) throws Exception {
    try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {
      PicocliShell shell = new PicocliShell(prompt, rootCommand, terminal.writer());
      return shell.run(args, terminal);
    }
  }

  /**
   * Returns the underlying picocli command line for advanced wiring.
   *
   * @return root command line
   */
  public CommandLine commandLine() {
    return commandLine;
  }

  /**
   * Returns the shell output writer.
   *
   * @return output writer
   */
  public PrintWriter out() {
    return out;
  }

  String prompt() {
    return prompt;
  }

  DefaultParser parser() {
    return parser;
  }

  ShellScriptContext interactiveContext() {
    return interactiveContext;
  }

  static LineReader activeLineReader() {
    return ACTIVE_LINE_READER.get();
  }

  static Terminal activeTerminal() {
    return ACTIVE_TERMINAL.get();
  }

  static String emptyTokenSentinel() {
    return EMPTY_TOKEN_SENTINEL;
  }

  /**
   * Runs the shell with the given startup arguments.
   *
   * @param args startup arguments
   * @return process-style exit code
   * @throws Exception on shell startup failure
   */
  public int run(String[] args) throws Exception {
    try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {
      return run(args, terminal);
    }
  }

  /**
   * Stops the interactive loop after the current command finishes.
   */
  public void stop() {
    running = false;
  }

  boolean isRunning() {
    return running;
  }

  ShellHelpSupport helpSupport() {
    return helpSupport;
  }

  void activateTerminal(Terminal terminal, LineReader reader) {
    ACTIVE_TERMINAL.set(terminal);
    ACTIVE_LINE_READER.set(reader);
  }

  void deactivateTerminal() {
    ACTIVE_LINE_READER.remove();
    ACTIVE_TERMINAL.remove();
  }

  private boolean isExecutingScript() {
    return sourceAction.isExecutingScript();
  }

  private int run(String[] args, Terminal terminal) {
    return interactiveRunner.run(args, terminal);
  }

  /**
   * Executes a single command line in the current shell context.
   *
   * @param line command line to execute
   * @return process-style exit code
   */
  public int executeLine(String line) {
    String trimmed = line == null ? "" : line.trim();
    if (trimmed.isEmpty() || trimmed.startsWith("#")) {
      return 0;
    }

    try {
      LOG.debug("interactive command: {}", trimmed);
      String expandedLine = expandText(trimmed, interactiveContext);
      ParsedLine parsedLine = parser.parse(protectEscapedDollarForParser(expandedLine), 0);
      String[] args = parsedLine.words().toArray(String[]::new);
      if (args.length > 0 && ("-h".equals(args[0]) || "--help".equals(args[0]))) {
        helpSupport.printDetachedUsage(helpSupport.resolveCommandSpec(args));
        return 0;
      }
      return commandLine.execute(args);
    } catch (Exception ex) {
      LOG.error("command failed: {}", trimmed, ex);
      ex.printStackTrace(out);
      out.flush();
      return 1;
    }
  }

  private int handleParameterException(ParameterException ex, String[] args) {
    LOG.error("command failed: {}", String.join(" ", args), ex);
    ex.printStackTrace(ex.getCommandLine().getErr());
    ex.getCommandLine().getErr().flush();
    return ex.getCommandLine().getCommandSpec().exitCodeOnInvalidInput();
  }

  private int handleExecutionException(Exception ex, CommandLine cmd) {
    if (ex instanceof ScriptCommandFailureException) {
      return cmd.getCommandSpec().exitCodeOnExecutionException();
    }

    LOG.error("command failed", ex);
    ex.printStackTrace(cmd.getErr());
    cmd.getErr().flush();
    return cmd.getCommandSpec().exitCodeOnExecutionException();
  }

  /**
   * Executes a script file without additional script arguments.
   *
   * @param fileName script file path
   * @return process-style exit code
   */
  public int executeScript(String fileName) {
    return sourceAction.executeScript(fileName);
  }

  /**
   * Executes a script file with positional script arguments.
   *
   * @param fileName script file path
   * @param args positional script arguments
   * @return process-style exit code
   */
  public int executeScript(String fileName, List<String> args) {
    return sourceAction.executeScript(fileName, args);
  }

  static boolean evaluateConditionWords(List<String> words, String header) {
    int index = 0;
    while (index < words.size()) {
      if (index + 2 >= words.size()) {
        throw new IllegalArgumentException("invalid condition: " + header);
      }

      String left = words.get(index++);
      String op = words.get(index++);
      boolean matched;
      if ("eq".equals(op)) {
        matched = left.equals(words.get(index++));
      } else if ("neq".equals(op)) {
        matched = !left.equals(words.get(index++));
      } else if ("in".equals(op)) {
        matched = false;
        while (index < words.size() && !isConditionSeparator(words.get(index))) {
          if (left.equals(words.get(index))) {
            matched = true;
          }
          index++;
        }
      } else {
        throw new IllegalArgumentException("unsupported operator: " + op);
      }

      if (matched) {
        return true;
      }

      if (index < words.size()) {
        String separator = words.get(index++);
        if (!isConditionSeparator(separator)) {
          throw new IllegalArgumentException("unsupported condition separator: " + separator);
        }
      }
    }

    return false;
  }

  private static boolean isConditionSeparator(String token) {
    return "|".equals(token) || "or".equals(token);
  }

  static String normalizeEmptyQuotedLiterals(String text) {
    return text.replace("\"\"", EMPTY_TOKEN_SENTINEL).replace("''", EMPTY_TOKEN_SENTINEL);
  }

  static List<String> restoreEmptyQuotedLiterals(List<String> words) {
    List<String> restored = new ArrayList<>(words.size());
    for (String word : words) {
      restored.add(EMPTY_TOKEN_SENTINEL.equals(word) ? "" : word);
    }
    return restored;
  }

  void executeSetStatement(String expr, ShellScriptContext context) {
    int firstSpace = expr.indexOf(' ');
    if (firstSpace == -1) {
      throw new IllegalArgumentException("set requires name and value");
    }

    String name = expr.substring(0, firstSpace).trim();
    String valueExpr = expr.substring(firstSpace + 1).trim();
    Object value = evaluateScriptValue(valueExpr, context);
    context.set(name, value);
  }

  void executeUnsetStatement(String expr, ShellScriptContext context) {
    String name = expr == null ? "" : expr.trim();
    if (name.isEmpty()) {
      throw new IllegalArgumentException("unset requires name");
    }
    context.unset(name);
  }

  private Object evaluateScriptValue(String expr, ShellScriptContext context) {
    String trimmed = expr == null ? "" : expr.trim();
    if (trimmed.isEmpty()) {
      return "";
    }
    if (trimmed.startsWith("$(") && trimmed.endsWith(")")) {
      String inner = trimmed.substring(2, trimmed.length() - 1).trim();
      try {
        ParsedLine parsed = parser.parse(expandText(inner, context), 0);
        List<String> words = parsed.words();
        if (words.size() >= 3) {
          return Boolean.toString(evaluateConditionWords(words, inner));
        }
      } catch (Exception ex) {
        // Fall through to normal text expansion when the expression is not a condition.
      }
    }
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      return parseListLiteral(trimmed, context);
    }
    return expandText(trimmed, context);
  }

  String executeCommandLine(
      String line, ShellScriptContext context, boolean captureOutput) {
    return commandExecutor.executeCommandLine(line, context, captureOutput);
  }

  List<String> parseWords(String line) {
    return commandExecutor.parseWords(line);
  }

  /**
   * JLine's parser treats backslash as an escape and would turn "\$" into "$".
   * We want "\${A}" to stay literally "\${A}" (with the backslash) so users can
   * suppress variable expansion.
   */
  private static String protectEscapedDollarForParser(String text) {
    return text == null ? "" : text;
  }

  private static String joinCommandArgs(List<String> words, int start) {
    return ShellCommandExecutor.joinCommandArgs(words, start);
  }

  String expandText(String text, ShellScriptContext context) {
    return commandExecutor.expandText(text, context);
  }

  static boolean endsWithContinuation(String line) {
    return ShellCommandExecutor.endsWithContinuation(line);
  }

  static String removeContinuation(String line) {
    return ShellCommandExecutor.removeContinuation(line);
  }

  private static List<String> parseListLiteral(String expr, ShellScriptContext context) {
    String body = expr.substring(1, expr.length() - 1).trim();
    if (body.isEmpty()) {
      return List.of();
    }
    List<String> items = new ArrayList<>();
    for (String token : body.split("\\s+")) {
      items.add(ShellVariableSupport.interpolateVariables(token, context));
    }
    return items;
  }

  void clearScreen() {
    interactiveRunner.clearScreen();
  }

  @Command(name = "echo", description = "Print text", mixinStandardHelpOptions = true)
  static class EchoCommand implements Runnable {

    private final PicocliShell shell;

    @Parameters(arity = "0..*", description = "Text to print")
    private List<String> words = Collections.emptyList();

    EchoCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      shell.out.println(ShellCommandExecutor.joinCommandArgs(words, 0));
      shell.out.flush();
    }
  }

  @Command(name = "sleep", description = "Sleep for the given number of seconds",
      mixinStandardHelpOptions = true)
  static class SleepCommand implements Runnable {

    @Parameters(index = "0", description = "Seconds to sleep")
    private double seconds;

    private final PicocliShell shell;

    SleepCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      long millis = (long) (seconds * 1000L);
      try {
        shell.out.println("Sleep for " + seconds + (seconds > 1 ? " seconds" : " second"));
        shell.out.flush();
        Thread.sleep(millis);
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("sleep interrupted", ex);
      }
    }
  }

  @Command(name = "exception", description = "Throw an exception with the given message",
      mixinStandardHelpOptions = true)
  static class ExceptionCommand implements Runnable {

    @Parameters(index = "0", description = "Exception message")
    private String message;

    @Override
    public void run() {
      throw new RuntimeException(message);
    }
  }

  @Command(name = "clear", description = "Clear the screen", mixinStandardHelpOptions = true)
  static class ClearCommand implements Runnable {

    private final PicocliShell shell;

    ClearCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      shell.clearScreen();
    }
  }

  @Command(name = "help", description = "Show help for a command", mixinStandardHelpOptions = true)
  static class ShellHelpCommand implements Runnable {

    private final PicocliShell shell;

    @Parameters(arity = "0..*", description = "Command path")
    private List<String> commandPath = Collections.emptyList();

    ShellHelpCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      CommandSpec spec = shell.commandLine.getCommandSpec();
      for (String name : commandPath) {
        CommandLine sub = spec.subcommands().get(name);
        if (sub == null) {
          throw new IllegalArgumentException("Unknown subcommand '" + name + "'.");
        }
        spec = sub.getCommandSpec();
      }
      shell.helpSupport.printDetachedUsage(spec);
    }
  }

  @Command(name = "exit", description = "Exit the shell", mixinStandardHelpOptions = true)
  static class ExitCommand implements Runnable {

    private final PicocliShell shell;

    ExitCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      shell.stop();
    }
  }

  @Command(name = "return", description = "Stop executing the current script",
      mixinStandardHelpOptions = true)
  static class ReturnCommand implements Runnable {

    private final PicocliShell shell;

    ReturnCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      if (!shell.isExecutingScript()) {
        throw new CommandLine.ParameterException(shell.commandLine,
            "return can only be used while executing a script");
      }

      throw SCRIPT_RETURN_SIGNAL;
    }
  }

  @Command(name = "set", description = "Set shell variable", mixinStandardHelpOptions = true)
  static class SetCommand implements Runnable {

    private final PicocliShell shell;

    @Parameters(index = "0", description = "Variable name")
    private String name;

    @Parameters(index = "1..*", arity = "1..*", description = "Variable value")
    private List<String> valueParts;

    SetCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      String value = String.join(" ", valueParts);
      shell.executeSetStatement(name + " " + value, shell.interactiveContext);
    }
  }

  @Command(name = "unset", description = "Unset shell variable", mixinStandardHelpOptions = true)
  static class UnsetCommand implements Runnable {

    private final PicocliShell shell;

    @Parameters(index = "0", description = "Variable name")
    private String name;

    UnsetCommand(PicocliShell shell) {
      this.shell = shell;
    }

    @Override
    public void run() {
      shell.executeUnsetStatement(name, shell.interactiveContext);
    }
  }

  static class Branch {

    private final String header;

    private final List<String> lines;

    Branch(String header, List<String> lines) {
      this.header = header;
      this.lines = lines;
    }

    String header() {
      return header;
    }

    List<String> lines() {
      return lines;
    }
  }

  static final class ScriptReturnSignal extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private ScriptReturnSignal() {
      super(null, null, false, false);
    }
  }

  static final class ScriptCommandFailureException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    ScriptCommandFailureException() {
      super(null, null, false, false);
    }
  }

}
