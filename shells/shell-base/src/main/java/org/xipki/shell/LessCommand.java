// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Attributes;
import org.jline.terminal.Terminal;
import org.jline.utils.InfoCmp.Capability;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;

/**
 * Action that pages through a text file.
 *
 * @author Lijun Liao (xipki)
 */
@Command(name = "less", description = "Page through a text file",
    mixinStandardHelpOptions = true)
class LessCommand implements Runnable {

  private final PicocliShell shell;

  @Parameters(index = "0", description = "Text file to display")
  @Completion(FilePathCompleter.class)
  private String file;

  LessCommand(PicocliShell shell) {
    this.shell = shell;
  }

  @Override
  public void run() {
    pageFile(file);
  }

  private void pageFile(String fileName) {
    Terminal terminal = PicocliShell.activeTerminal();
    if (terminal == null) {
      throw new RuntimeException("less is available only in interactive mode");
    }

    Path path = Paths.get(IoUtil.expandFilepath(fileName));
    List<String> lines;
    try {
      lines = Files.readAllLines(path, StandardCharsets.UTF_8);
    } catch (IOException ex) {
      throw new RuntimeException("could not read file " + fileName + ": " + ex.getMessage(), ex);
    }

    Attributes oldAttrs = terminal.enterRawMode();
    boolean alternateScreen = enterPagerScreen(terminal);
    int topLine = 0;
    String lastSearch = null;

    try {
      while (true) {
        int pageHeight = Math.max(1, terminal.getHeight() - 1);
        topLine = Math.max(0, Math.min(topLine, Math.max(0, lines.size() - 1)));
        renderPager(path, lines, topLine, pageHeight, lastSearch, terminal);

        int ch = terminal.reader().read();
        if (ch < 0 || ch == 'q' || ch == 'Q') {
          break;
        } else if (ch == ' ' || ch == 'f' || ch == 'F') {
          topLine = Math.min(Math.max(0, lines.size() - 1), topLine + pageHeight);
        } else if (ch == 'b' || ch == 'B') {
          topLine = Math.max(0, topLine - pageHeight);
        } else if (ch == 'j' || ch == 'J' || ch == '\n' || ch == '\r') {
          topLine = Math.min(Math.max(0, lines.size() - 1), topLine + 1);
        } else if (ch == 'k' || ch == 'K') {
          topLine = Math.max(0, topLine - 1);
        } else if (ch == 'g') {
          topLine = 0;
        } else if (ch == 'G') {
          topLine = Math.max(0, lines.size() - pageHeight);
        } else if (ch == 'h' || ch == 'H') {
          showPagerHelp(path, terminal);
        } else if (ch == '/') {
          terminal.setAttributes(oldAttrs);
          String pattern = readShellPrompt("/");
          oldAttrs = terminal.enterRawMode();
          if (StringUtil.isNotBlank(pattern)) {
            lastSearch = pattern;
            int found = findForward(lines, pattern, topLine + 1);
            if (found >= 0) {
              topLine = found;
            }
          }
        } else if (ch == 'n' || ch == 'N') {
          if (StringUtil.isNotBlank(lastSearch)) {
            int found = findForward(lines, lastSearch, topLine + 1);
            if (found >= 0) {
              topLine = found;
            }
          }
        } else if (ch == 27) {
          int next = terminal.reader().read();
          int third = terminal.reader().read();
          if (next == '[') {
            if (third == 'A') {
              topLine = Math.max(0, topLine - 1);
            } else if (third == 'B') {
              topLine = Math.min(Math.max(0, lines.size() - 1), topLine + 1);
            } else if (third == '5') {
              terminal.reader().read();
              topLine = Math.max(0, topLine - pageHeight);
            } else if (third == '6') {
              terminal.reader().read();
              topLine = Math.min(Math.max(0, lines.size() - 1), topLine + pageHeight);
            } else if (third == 'H') {
              topLine = 0;
            } else if (third == 'F') {
              topLine = Math.max(0, lines.size() - pageHeight);
            }
          }
        }
      }
    } catch (IOException ex) {
      throw new RuntimeException("less failed: " + ex.getMessage(), ex);
    } finally {
      terminal.setAttributes(oldAttrs);
      exitPagerScreen(terminal, alternateScreen);
    }
  }

  private boolean enterPagerScreen(Terminal terminal) {
    boolean alternateScreen = terminal.puts(Capability.enter_ca_mode);
    terminal.flush();
    if (!alternateScreen) {
      clearTerminal();
    }
    return alternateScreen;
  }

  private void exitPagerScreen(Terminal terminal, boolean alternateScreen) {
    if (alternateScreen) {
      terminal.puts(Capability.exit_ca_mode);
      terminal.flush();
    } else {
      shell.clearScreen();
    }
  }

  private void renderPager(Path path, List<String> lines, int topLine, int pageHeight,
      String highlightPattern, Terminal terminal) {
    clearTerminal();
    int width = Math.max(20, terminal.getWidth());
    int end = Math.min(lines.size(), topLine + pageHeight);
    for (int i = topLine; i < end; i++) {
      String line = lines.get(i);
      String renderedLine = highlightPagerLine(line, highlightPattern, width);
      if (renderedLine.length() > width && StringUtil.isBlank(highlightPattern)) {
        shell.out().println(renderedLine.substring(0, width));
      } else {
        shell.out().println(renderedLine);
      }
    }
    for (int i = end; i < topLine + pageHeight; i++) {
      shell.out().println("~");
    }

    int percent = lines.isEmpty() ? 100
        : Math.min(100, ((topLine + pageHeight) * 100) / lines.size());
    String status = String.format(
        "-- less -- %s  lines %d-%d/%d  %d%%  (q quit, h help, space/f next, "
            + "b back, j/k line, g/G ends, / search, n next)",
        path.getFileName(), lines.isEmpty() ? 0 : topLine + 1, end, lines.size(), percent);
    if (status.length() > width) {
      status = status.substring(0, width);
    }
    shell.out().print(status);
    shell.out().flush();
  }

  private String highlightPagerLine(String line, String pattern, int width) {
    if (StringUtil.isBlank(pattern)) {
      return line.length() > width ? line.substring(0, width) : line;
    }

    String lowerLine = line.toLowerCase(Locale.ROOT);
    String lowerPattern = pattern.toLowerCase(Locale.ROOT);
    int firstMatch = lowerLine.indexOf(lowerPattern);
    if (firstMatch < 0) {
      return line.length() > width ? line.substring(0, width) : line;
    }

    int visibleStart = 0;
    int visibleEnd = Math.min(line.length(), width);
    if (firstMatch >= width) {
      visibleStart = firstMatch;
      visibleEnd = Math.min(line.length(), visibleStart + width);
    }

    String visible = line.substring(visibleStart, visibleEnd);
    String visibleLower = lowerLine.substring(visibleStart, visibleEnd);
    int matchIndex = visibleLower.indexOf(lowerPattern);
    if (matchIndex < 0) {
      return visible;
    }

    StringBuilder sb = new StringBuilder(visible.length() + 16);
    int cursor = 0;
    while (matchIndex >= 0) {
      sb.append(visible, cursor, matchIndex);
      int matchEnd = Math.min(visible.length(), matchIndex + pattern.length());
      sb.append("\u001B[30;43;1m");
      sb.append(visible, matchIndex, matchEnd);
      sb.append("\u001B[0m");
      cursor = matchEnd;
      matchIndex = visibleLower.indexOf(lowerPattern, cursor);
    }
    sb.append(visible.substring(cursor));
    return sb.toString();
  }

  private void showPagerHelp(Path path, Terminal terminal) throws IOException {
    clearTerminal();
    List<String> helpLines = List.of(
        "less: " + path.getFileName(),
        "",
        "Supported keys:",
        "  q            quit",
        "  h            show this help",
        "  space, f     next page",
        "  b            previous page",
        "  j, Enter     next line",
        "  k            previous line",
        "  g            go to top",
        "  G            go to end",
        "  /pattern     search forward",
        "  n            next match",
        "  Up/Down      move one line",
        "  PgUp/PgDn    move one page",
        "  Home/End     go to top/end",
        "",
        "Press any key to return"
    );

    int width = Math.max(20, terminal.getWidth());
    for (String line : helpLines) {
      if (line.length() > width) {
        shell.out().println(line.substring(0, width));
      } else {
        shell.out().println(line);
      }
    }
    shell.out().flush();
    terminal.reader().read();
  }

  private static int findForward(List<String> lines, String pattern, int start) {
    String lower = pattern.toLowerCase(Locale.ROOT);
    for (int i = Math.max(0, start); i < lines.size(); i++) {
      if (lines.get(i).toLowerCase(Locale.ROOT).contains(lower)) {
        return i;
      }
    }
    return -1;
  }

  private String readShellPrompt(String prompt) throws IOException {
    String tmpPrompt = prompt;
    if (StringUtil.isNotBlank(prompt) && !prompt.endsWith(" ")) {
      tmpPrompt += " ";
    }

    LineReader reader = PicocliShell.activeLineReader();
    if (reader != null) {
      Object historyDisabledVar = reader.getVariable(LineReader.DISABLE_HISTORY);
      try {
        reader.setVariable(LineReader.DISABLE_HISTORY, Boolean.TRUE);
        return reader.readLine(tmpPrompt);
      } catch (UserInterruptException | EndOfFileException ex) {
        throw new IOException("interrupted", ex);
      } finally {
        if (historyDisabledVar != null) {
          reader.setVariable(LineReader.DISABLE_HISTORY, historyDisabledVar);
        } else {
          reader.getVariables().remove(LineReader.DISABLE_HISTORY);
        }
      }
    }

    shell.out().print(tmpPrompt);
    shell.out().flush();
    return new BufferedReader(new InputStreamReader(System.in)).readLine();
  }

  private void clearTerminal() {
    shell.out().print("\033[H\033[2J");
    shell.out().flush();
  }

}
