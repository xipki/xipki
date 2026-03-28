// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Executes parsed shell command lines, including builtins, local subcommands,
 * and external processes.
 *
 * @author Lijun Liao (xipki)
 */
class ShellCommandExecutor {

  private final PicocliShell shell;

  ShellCommandExecutor(PicocliShell shell) {
    this.shell = shell;
  }

  String executeCommandLine(String line, ShellScriptContext context, boolean captureOutput) {
    List<String> words = parseWords(ShellVariableSupport.interpolateVariables(line, context));
    if (words.isEmpty()) {
      return "";
    }

    String first = words.get(0);
    if ("echo".equals(first)) {
      String stdout = joinCommandArgs(words, 1) + System.lineSeparator();
      if (!captureOutput) {
        shell.out().print(stdout);
        shell.out().flush();
      }
      return stdout;
    } else if ("sleep".equals(first)) {
      double seconds = Double.parseDouble(words.get(1));
      shell.out().println("Sleep for " + seconds +  (seconds > 1 ? " seconds" : " second"));
      shell.out().flush();
      try {
        Thread.sleep((long) (seconds * 1000L));
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("sleep interrupted", ex);
      }
      return "";
    }

    if (hasLocalSubcommand(first)) {
      return executeLocalTokens(words, captureOutput);
    }

    try {
      return runProcess(words.toArray(new String[0]), captureOutput, context.workingDir());
    } catch (Exception ex) {
      throw new RuntimeException("failed to run process: " + ex.getMessage(), ex);
    }
  }

  private String runProcess(String[] command, boolean captureOutput, Path workingDir) {
    try {
      ProcessBuilder pb = new ProcessBuilder(command);
      pb.directory(workingDir.toFile());
      Process process = pb.start();
      byte[] stdout = process.getInputStream().readAllBytes();
      byte[] stderr = process.getErrorStream().readAllBytes();
      int rc = process.waitFor();
      String stdoutText = new String(stdout, StandardCharsets.UTF_8);
      String stderrText = new String(stderr, StandardCharsets.UTF_8);
      if (!captureOutput && !stderrText.isEmpty()) {
        shell.out().print(stderrText);
        shell.out().flush();
      }
      if (rc != 0) {
        throw new RuntimeException("command failed: " + String.join(" ", command)
            + (stderrText.isEmpty() ? "" : ": " + stderrText.trim()));
      }
      return stdoutText;
    } catch (IOException | InterruptedException ex) {
      if (ex instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new RuntimeException("could not execute command " + String.join(" ", command), ex);
    }
  }

  private boolean hasLocalSubcommand(String name) {
    return shell.commandLine().getCommandSpec().subcommands().containsKey(name);
  }

  private String executeLocalTokens(List<String> tokens, boolean captureOutput) {
    if (captureOutput) {
      StringWriter stdout = new StringWriter();
      StringWriter stderr = new StringWriter();
      PrintWriter oldOut = shell.commandLine().getOut();
      PrintWriter oldErr = shell.commandLine().getErr();
      try {
        shell.commandLine().setOut(new PrintWriter(stdout, true));
        shell.commandLine().setErr(new PrintWriter(stderr, true));
        int rc = shell.commandLine().execute(tokens.toArray(String[]::new));
        if (rc != 0) {
          String errText = stderr.toString().trim();
          throw new RuntimeException("command failed: " + String.join(" ", tokens)
              + (errText.isEmpty() ? "" : ": " + errText));
        }
        return stdout.toString();
      } finally {
        shell.commandLine().setOut(oldOut);
        shell.commandLine().setErr(oldErr);
      }
    }

    int rc = shell.commandLine().execute(tokens.toArray(String[]::new));
    if (rc != 0) {
      throw new PicocliShell.ScriptCommandFailureException();
    }
    return "";
  }

  private String substituteCommandOutput(String text, ShellScriptContext context) {
    String current = text;
    int start = current.indexOf("$(");
    while (start >= 0) {
      int end = findCommandSubstitutionEnd(current, start);
      if (end == -1) {
        throw new IllegalArgumentException("unterminated command substitution: " + text);
      }

      String inner = current.substring(start + 2, end).trim();
      String replacement = executeCommandLine(inner, context, true).trim();
      current = current.substring(0, start) + replacement + current.substring(end + 1);
      start = current.indexOf("$(");
    }
    return current;
  }

  private static int findCommandSubstitutionEnd(String text, int start) {
    int depth = 0;
    boolean inSingle = false;
    boolean inDouble = false;
    for (int i = start; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (ch == '\'' && !inDouble) {
        inSingle = !inSingle;
      } else if (ch == '"' && !inSingle) {
        inDouble = !inDouble;
      }
      if (inSingle || inDouble) {
        continue;
      }
      if (i + 1 < text.length() && text.charAt(i) == '$' && text.charAt(i + 1) == '(') {
        depth++;
        i++;
      } else if (ch == ')') {
        depth--;
        if (depth == 0) {
          return i;
        }
      }
    }
    return -1;
  }

  private static String protectEscapedDollarForParser(String text) {
    return text == null ? "" : text;
  }

  private static String normalizeEmptyQuotedLiterals(String text) {
    return text.replace("\"\"", PicocliShell.emptyTokenSentinel())
        .replace("''", PicocliShell.emptyTokenSentinel());
  }

  private static List<String> restoreEmptyQuotedLiterals(List<String> words) {
    List<String> restored = new ArrayList<>(words.size());
    for (String word : words) {
      restored.add(PicocliShell.emptyTokenSentinel().equals(word) ? "" : word);
    }
    return restored;
  }

  List<String> parseWords(String line) {
    try {
      String normalized = protectEscapedDollarForParser(normalizeEmptyQuotedLiterals(line));
      return restoreEmptyQuotedLiterals(shell.parser().parse(normalized, 0).words());
    } catch (Exception ex) {
      throw new IllegalArgumentException("could not parse line: " + line, ex);
    }
  }

  String expandText(String text, ShellScriptContext context) {
    String expanded = ShellVariableSupport.interpolateVariables(text, context);
    return substituteCommandOutput(expanded, context);
  }

  static boolean endsWithContinuation(String line) {
    int len = line.length();
    while (len > 0 && Character.isWhitespace(line.charAt(len - 1))) {
      len--;
    }
    return len > 0 && line.charAt(len - 1) == '\\';
  }

  static String removeContinuation(String line) {
    int len = line.length();
    while (len > 0 && Character.isWhitespace(line.charAt(len - 1))) {
      len--;
    }
    return len > 0 ? line.substring(0, len - 1) : line;
  }

  static String joinCommandArgs(List<String> words, int start) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < words.size(); i++) {
      if (i > start) {
        sb.append(' ');
      }
      sb.append(words.get(i));
    }
    return sb.toString();
  }

}
