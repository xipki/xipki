// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.Candidate;
import org.jline.reader.ParsedLine;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.shell.completer.DirPathCompleter;
import org.xipki.shell.completer.FilePathCompleter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Tests for annotation-driven completion behavior.
 *
 * @author Lijun Liao (xipki)
 */
public class ShellCompleterTest {

  @Test
  public void testCompletionValuesOnly() {
    List<String> values = complete("--static ", new StaticOnlyCommand());
    Assert.assertEquals(List.of("ALPHA", "BETA"), values);
  }

  @Test
  public void testCompletionProviderOnly() {
    List<String> values = complete("--provider ", new ProviderOnlyCommand());
    Assert.assertEquals(List.of("DYNAMIC"), values);
  }

  @Test
  public void testCompletionValuesMergedWithProvider() {
    List<String> values = complete("--merged ", new MergedCommand());
    Assert.assertEquals(List.of("STATIC", "DYNAMIC"), values);
  }

  @Test
  public void testCompletionValuesDeduplicated() {
    List<String> values = complete("--dedup ", new DedupCommand());
    Assert.assertEquals(List.of("SHARED", "STATIC", "DYNAMIC"), values);
  }

  @Test
  public void testWindowsRelativeFilePathCompletion() throws Exception {
    Path shellHome = Files.createTempDirectory("xipki-shell-win-file");
    Files.createDirectories(shellHome.resolve("subdir"));
    Files.writeString(shellHome.resolve("subdir").resolve("file.txt"), "test");

    withShellHome(shellHome, () -> {
      List<String> values = complete("--file subdir\\fi", new PathCommand());
      Assert.assertEquals(List.of("subdir\\file.txt"), values);
    });
  }

  @Test
  public void testWindowsRelativeDirPathCompletion() throws Exception {
    Path shellHome = Files.createTempDirectory("xipki-shell-win-dir");
    Files.createDirectories(shellHome.resolve("subdir").resolve("dir"));
    Files.writeString(shellHome.resolve("subdir").resolve("file.txt"), "test");

    withShellHome(shellHome, () -> {
      List<String> values = complete("--dir subdir\\di", new PathCommand());
      Assert.assertEquals(List.of("subdir\\dir\\"), values);
    });
  }

  @Test
  public void testWindowsDriveFilePathCompletion() throws Exception {
    Path shellHome = Files.createTempDirectory("xipki-shell-win-drive");
    Path baseDir;
    String typedPrefix;
    if (isWindowsHost()) {
      baseDir = shellHome.resolve("temp");
      typedPrefix = shellHome.toString().replace('/', '\\') + "\\te";
    } else {
      baseDir = shellHome.resolve("C:").resolve("temp");
      typedPrefix = "C:\\temp\\fi";
    }

    Files.createDirectories(baseDir);
    Files.writeString(baseDir.resolve(isWindowsHost() ? "test.txt" : "file.txt"), "test");

    withShellHome(shellHome, () -> {
      List<String> values = complete("--file " + typedPrefix, new PathCommand());
      Assert.assertEquals(List.of(isWindowsHost()
          ? shellHome.toString().replace('/', '\\') + "\\temp\\"
              + baseDir.resolve("test.txt").getFileName()
          : "C:\\temp\\file.txt"), values);
    });
  }

  @Test
  public void testWindowsFileUriPathCompletion() throws Exception {
    Path shellHome = Files.createTempDirectory("xipki-shell-win-file-uri");
    Files.createDirectories(shellHome.resolve("subdir"));
    Files.writeString(shellHome.resolve("subdir").resolve("file.txt"), "test");

    withShellHome(shellHome, () -> {
      List<String> values = complete("--file file:subdir\\fi", new PathCommand());
      Assert.assertEquals(List.of("file:subdir\\file.txt"), values);
    });
  }

  @Test
  public void testPosixPathCompletionUnchanged() throws Exception {
    Path shellHome = Files.createTempDirectory("xipki-shell-posix");
    Files.createDirectories(shellHome.resolve("subdir"));
    Files.writeString(shellHome.resolve("subdir").resolve("file.txt"), "test");

    withShellHome(shellHome, () -> {
      List<String> values = complete("--file subdir/fi", new PathCommand());
      Assert.assertEquals(List.of("subdir/file.txt"), values);
    });
  }

  @Test
  public void testTildePathCompletion() throws Exception {
    Path userHome = Files.createTempDirectory("xipki-shell-home");
    Files.createDirectories(userHome.resolve("docs"));
    Files.writeString(userHome.resolve("file.txt"), "test");

    withUserHome(userHome, () -> {
      List<String> values = complete("--file ~/", new PathCommand());
      Assert.assertTrue(values.contains("~/docs/"));
      Assert.assertTrue(values.contains("~/file.txt"));
    });
  }

  @Test
  public void testRootPathCompletionKeepsLeadingSlash() {
    List<String> values = complete("--file /e", new PathCommand());
    Assert.assertTrue(values.contains("/etc/"));
  }

  private static List<String> complete(String line, Object command) {
    CommandLine commandLine = new CommandLine(command);
    ShellCompleter completer = new ShellCompleter(commandLine.getCommandSpec());
    List<Candidate> candidates = new ArrayList<>();
    completer.complete(null, parsedLine(line), candidates);
    return candidates.stream().map(Candidate::value).collect(Collectors.toList());
  }

  private static ParsedLine parsedLine(String line) {
    String raw = line == null ? "" : line;
    boolean trailingSpace = !raw.isEmpty() && Character.isWhitespace(raw.charAt(raw.length() - 1));
    String trimmed = raw.trim();
    List<String> words = new ArrayList<>();
    if (!trimmed.isEmpty()) {
      words.addAll(List.of(trimmed.split("\\s+")));
    }
    if (trailingSpace) {
      words.add("");
    }

    int wordIndex = words.isEmpty() ? 0 : words.size() - 1;
    String word = words.isEmpty() ? "" : words.get(wordIndex);
    return new TestParsedLine(raw, words, wordIndex, word);
  }

  @Command(name = "static-only")
  private static class StaticOnlyCommand implements Runnable {

    @Option(names = "--static")
    @Completion(values = {"ALPHA", "BETA"})
    private String value;

    @Override
    public void run() {
    }
  }

  @Command(name = "provider-only")
  private static class ProviderOnlyCommand implements Runnable {

    @Option(names = "--provider")
    @Completion(DynamicProvider.class)
    private String value;

    @Override
    public void run() {
    }
  }

  @Command(name = "merged")
  private static class MergedCommand implements Runnable {

    @Option(names = "--merged")
    @Completion(value = DynamicProvider.class, values = {"STATIC"})
    private String value;

    @Override
    public void run() {
    }
  }

  @Command(name = "dedup")
  private static class DedupCommand implements Runnable {

    @Option(names = "--dedup")
    @Completion(value = DuplicateProvider.class, values = {"SHARED", "STATIC"})
    private String value;

    @Override
    public void run() {
    }
  }

  public static class DynamicProvider implements CompletionProvider {

    @Override
    public Set<String> complete(CommandLine.Model.CommandSpec commandSpec,
        CommandLine.Model.ArgSpec argSpec, List<String> words, int wordIndex) {
      return Set.of("DYNAMIC");
    }
  }

  public static class DuplicateProvider implements CompletionProvider {

    @Override
    public Set<String> complete(CommandLine.Model.CommandSpec commandSpec,
        CommandLine.Model.ArgSpec argSpec, List<String> words, int wordIndex) {
      Set<String> values = new LinkedHashSet<>();
      values.add("SHARED");
      values.add("DYNAMIC");
      return values;
    }
  }

  @Command(name = "path")
  private static class PathCommand implements Runnable {

    @Option(names = "--file")
    @Completion(FilePathCompleter.class)
    private String file;

    @Option(names = "--dir")
    @Completion(DirPathCompleter.class)
    private String dir;

    @Override
    public void run() {
    }
  }

  private static boolean isWindowsHost() {
    return System.getProperty("os.name", "").toLowerCase().contains("win");
  }

  private static void withShellHome(Path shellHome, ThrowingRunnable runnable) throws Exception {
    String old = System.getProperty("org.xipki.shell.home");
    System.setProperty("org.xipki.shell.home", shellHome.toString());
    try {
      runnable.run();
    } finally {
      if (old == null) {
        System.clearProperty("org.xipki.shell.home");
      } else {
        System.setProperty("org.xipki.shell.home", old);
      }
    }
  }

  private static void withUserHome(Path userHome, ThrowingRunnable runnable) throws Exception {
    String old = System.getProperty("user.home");
    System.setProperty("user.home", userHome.toString());
    try {
      runnable.run();
    } finally {
      if (old == null) {
        System.clearProperty("user.home");
      } else {
        System.setProperty("user.home", old);
      }
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {

    void run() throws Exception;

  }

  private static class TestParsedLine implements ParsedLine {

    private final String line;

    private final List<String> words;

    private final int wordIndex;

    private final String word;

    private TestParsedLine(String line, List<String> words, int wordIndex, String word) {
      this.line = line;
      this.words = words;
      this.wordIndex = wordIndex;
      this.word = word;
    }

    @Override
    public String word() {
      return word;
    }

    @Override
    public int wordCursor() {
      return word == null ? 0 : word.length();
    }

    @Override
    public int wordIndex() {
      return wordIndex;
    }

    @Override
    public List<String> words() {
      return words;
    }

    @Override
    public String line() {
      return line;
    }

    @Override
    public int cursor() {
      return line.length();
    }
  }
}
