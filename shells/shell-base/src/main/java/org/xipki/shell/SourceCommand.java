// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.ParsedLine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.shell.completer.FilePathCompleter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Action that executes commands from a script file.
 *
 * @author Lijun Liao (xipki)
 */
@Command(name = "source", description = "Execute commands from script file",
    mixinStandardHelpOptions = true)
class SourceCommand implements Callable<Integer> {

  private static final Logger LOG = LoggerFactory.getLogger(SourceCommand.class);

  private static final String SCRIPT_TRACE_VARIABLE = "SCRIPT_TRACE";

  private final PicocliShell shell;

  private final Set<Path> executingScripts = new LinkedHashSet<>();

  @Parameters(index = "0", description = "script file")
  @Completion(FilePathCompleter.class)
  private String scriptFile;

  @Parameters(index = "1..*", arity = "0..*", description = "optional arguments")
  private List<String> scriptArgs;

  SourceCommand(PicocliShell shell) {
    this.shell = shell;
  }

  boolean isExecutingScript() {
    return !executingScripts.isEmpty();
  }

  int executeScript(String fileName) {
    ShellScriptContext context = shell.interactiveContext();
    return executeScript(Paths.get(stripFilePrefix(fileName)), context.workingDir(),
        context.child(List.of()));
  }

  int executeScript(String fileName, List<String> args) {
    ShellScriptContext context = shell.interactiveContext();
    return executeScript(Paths.get(stripFilePrefix(fileName)), context.workingDir(),
        context.child(args));
  }

  @Override
  public Integer call() {
    return executeScript(scriptFile, scriptArgs == null ? List.of() : scriptArgs);
  }

  private int executeScript(Path scriptPath, Path baseDir, ShellScriptContext context) {
    Path resolved = resolveScriptPath(scriptPath, baseDir);
    Path normalized = resolved.toAbsolutePath().normalize();
    if (!Files.isRegularFile(normalized)) {
      throw new IllegalArgumentException("script file not found: " + normalized);
    }
    if (!executingScripts.add(normalized)) {
      throw new IllegalArgumentException("recursive source detected: " + normalized);
    }

    try {
      LOG.debug("enter script: {}", normalized);
      List<String> lines = mergeContinuedLines(Files.readAllLines(normalized));
      Path workingDir = normalized.getParent() == null ? Paths.get(".") : normalized.getParent();
      executeScriptLines(lines, context.withWorkingDir(workingDir));
      return 0;
    } catch (PicocliShell.ScriptReturnSignal ex) {
      return 0;
    } catch (PicocliShell.ScriptCommandFailureException ex) {
      return 1;
    } catch (IOException ex) {
      throw new RuntimeException("could not read script " + normalized + ": " + ex.getMessage(),
          ex);
    } finally {
      LOG.debug("leave script: {}", normalized);
      executingScripts.remove(normalized);
    }
  }

  private void executeScriptLines(List<String> lines, ShellScriptContext context) {
    for (int i = 0; i < lines.size(); i++) {
      String raw = lines.get(i);
      String trimmed = raw == null ? "" : raw.trim();
      if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
        continue;
      }

      if (trimmed.startsWith("if ")) {
        LOG.debug("script command: {}", trimmed);
        printScriptCommand(trimmed, context);
        int end = findMatchingFi(lines, i);
        executeIfBlock(lines.subList(i, end + 1), context);
        i = end;
        continue;
      }

      if (trimmed.startsWith("for ")) {
        LOG.debug("script command: {}", trimmed);
        printScriptCommand(trimmed, context);
        int end = findMatchingDone(lines, i);
        executeForBlock(lines.subList(i, end + 1), context);
        i = end;
        continue;
      }

      LOG.debug("script command: {}", trimmed);
      printScriptCommand(trimmed, context);
      executeScriptStatement(trimmed, context);
    }
  }

  private void printScriptCommand(String command, ShellScriptContext context) {
    if (!context.isTrue(SCRIPT_TRACE_VARIABLE)) {
      return;
    }

    shell.out().println(formatDisplayedCommand(command));
    shell.out().flush();
  }

  private String formatDisplayedCommand(String command) {
    List<String> words;
    try {
      words = shell.parseWords(command);
    } catch (Exception ex) {
      return command;
    }

    return words.isEmpty() ? command : ShellCommandStyler.formatAnsi(words);
  }

  private void executeIfBlock(List<String> blockLines, ShellScriptContext context) {
    List<PicocliShell.Branch> branches = new ArrayList<>();
    List<String> elseLines = new ArrayList<>();

    String currentHeader = blockLines.get(0).trim();
    List<String> currentBody = new ArrayList<>();
    int nested = 0;
    for (int i = 1; i < blockLines.size() - 1; i++) {
      String line = blockLines.get(i);
      String trimmed = line == null ? "" : line.trim();
      if (trimmed.startsWith("if ")) {
        nested++;
        currentBody.add(line);
        continue;
      }
      if ("fi".equals(trimmed)) {
        nested--;
        currentBody.add(line);
        continue;
      }

      if (nested == 0 && (trimmed.startsWith("elif ") || "else".equals(trimmed))) {
        branches.add(new PicocliShell.Branch(currentHeader, new ArrayList<>(currentBody)));
        currentBody.clear();
        currentHeader = trimmed;
      } else {
        currentBody.add(line);
      }
    }

    if ("else".equals(currentHeader)) {
      elseLines.addAll(currentBody);
    } else {
      branches.add(new PicocliShell.Branch(currentHeader, currentBody));
    }

    for (PicocliShell.Branch branch : branches) {
      if (evaluateCondition(branch.header(), context)) {
        executeScriptLines(branch.lines(), context);
        return;
      }
    }

    if (!elseLines.isEmpty()) {
      executeScriptLines(elseLines, context);
    }
  }

  private void executeForBlock(List<String> blockLines, ShellScriptContext context) {
    String header = blockLines.get(0).trim();
    List<String> tokens = shell.parseWords(shell.expandText(header, context));
    if (tokens.size() < 4 || !"in".equals(tokens.get(2))) {
      throw new IllegalArgumentException("invalid for syntax: " + header);
    }

    String varName = tokens.get(1);
    List<String> values = new ArrayList<>(tokens.subList(3, tokens.size()));
    List<String> body = blockLines.subList(1, blockLines.size() - 1);
    for (String value : values) {
      context.set(varName, value);
      executeScriptLines(body, context);
    }
  }

  private boolean evaluateCondition(String header, ShellScriptContext context) {
    String expression;
    if (header.startsWith("if ")) {
      expression = header.substring(3).trim();
    } else if (header.startsWith("elif ")) {
      expression = header.substring(5).trim();
    } else {
      throw new IllegalArgumentException("unsupported control line: " + header);
    }

    try {
      String normalized = PicocliShell.normalizeEmptyQuotedLiterals(
                            shell.expandText(expression, context));
      ParsedLine parsed = shell.parser().parse(normalized, 0);
      List<String> words = PicocliShell.restoreEmptyQuotedLiterals(parsed.words());
      return PicocliShell.evaluateConditionWords(words, header);
    } catch (RuntimeException ex) {
      throw new RuntimeException("could not parse condition: " + header, ex);
    }
  }

  private int findMatchingFi(List<String> lines, int start) {
    int depth = 0;
    for (int i = start; i < lines.size(); i++) {
      String trimmed = lines.get(i) == null ? "" : lines.get(i).trim();
      if (trimmed.startsWith("if ") || trimmed.startsWith("for ")) {
        depth++;
      } else if ("fi".equals(trimmed) || "done".equals(trimmed)) {
        depth--;
        if ("fi".equals(trimmed) && depth == 0) {
          return i;
        }
      }
    }
    throw new IllegalArgumentException("missing fi for if block");
  }

  private int findMatchingDone(List<String> lines, int start) {
    int depth = 0;
    for (int i = start; i < lines.size(); i++) {
      String trimmed = lines.get(i) == null ? "" : lines.get(i).trim();
      if (trimmed.startsWith("for ") || trimmed.startsWith("if ")) {
        depth++;
      } else if ("done".equals(trimmed) || "fi".equals(trimmed)) {
        depth--;
        if ("done".equals(trimmed) && depth == 0) {
          return i;
        }
      }
    }
    throw new IllegalArgumentException("missing done for for block");
  }

  private void executeScriptStatement(String line, ShellScriptContext context) {
    if (line.startsWith("set ")) {
      shell.executeSetStatement(line.substring(4).trim(), context);
      return;
    }

    if (line.startsWith("unset ")) {
      shell.executeUnsetStatement(line.substring(6).trim(), context);
      return;
    }

    executeScriptCommand(line, context);
  }

  private void executeScriptCommand(String line, ShellScriptContext context) {
    if (line.startsWith("source ")) {
      try {
        ParsedLine parsed = shell.parser().parse(shell.expandText(line, context), 0);
        List<String> words = parsed.words();
        if (words.size() < 2) {
          throw new IllegalArgumentException("source requires a script file");
        }
        List<String> args = words.size() > 2 ? new ArrayList<>(words.subList(2, words.size()))
            : context.args();
        int rc = executeScript(Paths.get(words.get(1)), context.workingDir(), context.child(args));
        if (rc != 0) {
          throw new PicocliShell.ScriptCommandFailureException();
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not execute source command", ex);
      }
      return;
    }

    if ("return".equals(line)) {
      new PicocliShell.ReturnCommand(shell).run();
      return;
    }

    shell.executeCommandLine(line, context, false);
  }

  private static Path resolveScriptPath(Path scriptPath, Path baseDir) {
    if (scriptPath.isAbsolute()) {
      return scriptPath;
    }

    Path effectiveBase = baseDir == null ? Paths.get(".") : baseDir;
    Path cwdPath = effectiveBase.resolve(scriptPath).normalize();
    if (Files.exists(cwdPath)) {
      return cwdPath;
    }

    Path shellHomePath = ShellUtil.shellHome().resolve(scriptPath).normalize();
    if (Files.exists(shellHomePath)) {
      return shellHomePath;
    }

    return cwdPath;
  }

  private static List<String> mergeContinuedLines(List<String> rawLines) {
    List<String> lines = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    for (String rawLine : rawLines) {
      String line = rawLine == null ? "" : rawLine;
      boolean continued = PicocliShell.endsWithContinuation(line);
      String part = continued ? PicocliShell.removeContinuation(line) : line;

      if (current.length() > 0) {
        String trimmedPart = part.trim();
        if (!trimmedPart.isEmpty()) {
          if (!Character.isWhitespace(current.charAt(current.length() - 1))) {
            current.append(' ');
          }
          current.append(trimmedPart);
        }
      } else if (continued) {
        current.append(part.trim());
      } else {
        lines.add(line);
      }

      if (continued) {
        continue;
      }

      if (current.length() > 0) {
        lines.add(current.toString());
        current.setLength(0);
      }
    }

    if (current.length() > 0) {
      lines.add(current.toString());
    }
    return lines;
  }

  private static String stripFilePrefix(String target) {
    return target.startsWith("file:") ? target.substring("file:".length()) : target;
  }

}
