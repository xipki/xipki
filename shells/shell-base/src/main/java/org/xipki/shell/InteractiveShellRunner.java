// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Terminal;
import org.jline.utils.InfoCmp.Capability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Runs the interactive shell loop, including terminal setup, history, prompts, and startup output.
 *
 * @author Lijun Liao (xipki)
 */
class InteractiveShellRunner {

  private static final Logger LOG = LoggerFactory.getLogger(InteractiveShellRunner.class);

  private final PicocliShell shell;

  InteractiveShellRunner(PicocliShell shell) {
    this.shell = shell;
  }

  int run(String[] args, Terminal terminal) {
    shell.helpSupport().stripVersionOptions(shell.commandLine().getCommandSpec());
    shell.helpSupport().flattenQualifiedNames(shell.commandLine().getCommandSpec());
    if (args != null && args.length > 0) {
      if (isHelpRequest(args)) {
        shell.helpSupport().printDetachedUsage(shell.helpSupport().resolveCommandSpec(args));
        return 0;
      }
      return shell.commandLine().execute(args);
    }
    runInteractive(terminal);
    return 0;
  }

  void runInteractive(Terminal terminal) {
    LineReader reader = LineReaderBuilder.builder()
        .terminal(terminal)
        .parser(shell.parser())
        .history(new ShellHistorySupport.MaskingHistory())
        .highlighter(ShellCommandStyler.highlighter())
        .completer(new ShellCompleter(shell.commandLine().getCommandSpec()))
        .build();
    Path historyFile = resolveHistoryFile();
    try {
      Path parent = historyFile.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
    } catch (IOException ex) {
      throw new RuntimeException("could not create history directory for " + historyFile, ex);
    }
    reader.setVariable(LineReader.HISTORY_FILE, historyFile);

    boolean startupMessagePrinted = false;
    while (shell.isRunning()) {
      try {
        shell.activateTerminal(terminal, reader);
        if (!startupMessagePrinted) {
          prepareFreshLine(terminal);
          printStartupMessage();
          startupMessagePrinted = true;
        }
        String line = readInteractiveCommand(reader);
        shell.executeLine(line);
      } catch (UserInterruptException ex) {
        shell.out().println("^C");
        shell.out().flush();
      } catch (EndOfFileException ex) {
        shell.out().println();
        shell.out().flush();
        break;
      } finally {
        shell.deactivateTerminal();
      }
    }
  }

  void clearScreen() {
    shell.out().print("\033[H\033[2J");
    shell.out().flush();
    Terminal activeTerminal = PicocliShell.activeTerminal();
    if (activeTerminal != null) {
      prepareFreshLine(activeTerminal);
    }
    printStartupMessage();
  }

  private static boolean isHelpRequest(String[] args) {
    for (String arg : args) {
      if ("-h".equals(arg) || "--help".equals(arg)) {
        return true;
      }
    }
    return false;
  }

  private Path resolveHistoryFile() {
    String commandName = shell.commandLine().getCommandName();
    String fileName = commandName + ".history";
    return Paths.get(System.getProperty("user.home"), ".xipki", fileName);
  }

  private void printWelcome() {
    String commandName = shell.commandLine().getCommandName();
    String version = determineVersion();
    shell.out().println("Welcome to " + commandName + " " + version);
    shell.out().flush();
  }

  private void printStartupMessage() {
    printWelcome();
    shell.out().println("Type 'help' for commands, 'exit' to quit.");
    shell.out().flush();
  }

  private static void prepareFreshLine(Terminal terminal) {
    terminal.puts(Capability.carriage_return);
    terminal.puts(Capability.clr_eol);
    terminal.flush();
  }

  private String determineVersion() {
    Class<?> rootClass = shell.commandLine().getCommandSpec().userObject().getClass();

    Package pkg = rootClass.getPackage();
    if (pkg != null) {
      String version = pkg.getImplementationVersion();
      if (StringUtil.isNotBlank(version)) {
        return version;
      }
    }

    String commandName = shell.commandLine().getCommandName();
    String resource = "META-INF/maven/org.xipki.shell/" + commandName + "/pom.properties";
    try (InputStream in = rootClass.getClassLoader().getResourceAsStream(resource)) {
      if (in != null) {
        Properties props = new Properties();
        props.load(in);
        String version = props.getProperty("version");
        if (StringUtil.isNotBlank(version)) {
          return version;
        }
      }
    } catch (IOException ex) {
      LOG.debug("could not read version from {}", resource, ex);
    }

    return "unknown";
  }

  private String readInteractiveCommand(LineReader reader) {
    StringBuilder command = new StringBuilder();
    String currentPrompt = shell.prompt();
    while (true) {
      String line = reader.readLine(currentPrompt);
      if (command.length() > 0) {
        appendInteractiveContinuation(command, line);
      } else {
        command.append(line);
      }

      if (!ShellCommandExecutor.endsWithContinuation(command.toString())) {
        return command.toString();
      }

      String merged = ShellCommandExecutor.removeContinuation(command.toString()).stripTrailing();
      command.setLength(0);
      command.append(merged);
      currentPrompt = "> ";
    }
  }

  private static void appendInteractiveContinuation(StringBuilder command, String line) {
    String trimmed = line == null ? "" : line.trim();
    if (trimmed.isEmpty()) {
      return;
    }

    if (command.length() > 0 && !Character.isWhitespace(command.charAt(command.length() - 1))) {
      command.append(' ');
    }
    command.append(trimmed);
  }

}
