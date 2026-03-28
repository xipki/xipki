// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.Candidate;
import org.jline.reader.Completer;
import org.jline.reader.LineReader;
import org.jline.reader.ParsedLine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Model.PositionalParamSpec;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Provides JLine tab completion for shell commands, options, argument values, and paths.
 *
 * @author Lijun Liao (xipki)
 */
class ShellCompleter implements Completer {

  private static final Logger LOG = LoggerFactory.getLogger(ShellCompleter.class);

  private static final List<String> TRUE_FALSE = List.of("true", "false");

  private static final boolean WINDOWS_HOST =
      System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

  private final CommandSpec rootSpec;

  ShellCompleter(CommandSpec rootSpec) {
    this.rootSpec = rootSpec;
  }

  @Override
  public void complete(LineReader reader, ParsedLine line, List<Candidate> candidates) {
    List<String> words = line.words();
    int wordIndex = line.wordIndex();
    String currentWord = line.word() == null ? "" : line.word();

    if (words.isEmpty() || wordIndex == 0) {
      addSubcommands(rootSpec, candidates);
      return;
    }

    ResolvedCommand resolved = resolveCommand(rootSpec, words, wordIndex, currentWord);
    CommandSpec spec = resolved.spec;
    if (isSourceFileContext(spec, wordIndex, resolved.commandWords, currentWord)) {
      addPathCandidates(currentWord, "", candidates, false, true);
      return;
    }

    if (resolved.completeSubcommands) {
      addSubcommands(spec, candidates);
      if (currentWord.isEmpty() || currentWord.startsWith("-")) {
        addOptions(spec, candidates);
      }
      return;
    }

    if (currentWord.startsWith("-")) {
      addOptions(spec, candidates);
      return;
    }

    OptionSpec option = findActiveOption(spec, words, wordIndex, resolved.commandWords);
    if (option != null) {
      addOptionValues(spec, option, words, wordIndex, currentWord, candidates);
      return;
    }

    PositionalParamSpec positional =
        findActivePositional(spec, words, wordIndex, resolved.commandWords);
    if (positional != null) {
      addPositionalValues(spec, positional, words, wordIndex, currentWord, candidates);
      return;
    }

    if (currentWord.isEmpty()) {
      addSubcommands(spec, candidates);
      addOptions(spec, candidates);
      return;
    }

    addSubcommands(spec, candidates);
    addOptions(spec, candidates);
  }

  private static OptionSpec findActiveOption(
      CommandSpec spec, List<String> words, int wordIndex, int commandWords) {
    if (wordIndex <= 0 || wordIndex > words.size()) {
      return null;
    }

    String prev = wordIndex < words.size() ? words.get(wordIndex - 1) : null;
    if (prev != null && prev.startsWith("-")) {
      return spec.findOption(prev);
    }

    for (int i = wordIndex - 1; i >= commandWords; i--) {
      String token = words.get(i);
      if (!token.startsWith("-")) {
        continue;
      }

      OptionSpec option = spec.findOption(token);
      if (option == null || option.arity().max() == 0) {
        continue;
      }

      int valueCount = 0;
      for (int j = i + 1; j < wordIndex; j++) {
        String valueToken = words.get(j);
        if (valueToken.startsWith("-")) {
          break;
        }
        valueCount++;
      }

      if (valueCount < option.arity().max()) {
        return option;
      }
    }

    return null;
  }

  private static PositionalParamSpec findActivePositional(
      CommandSpec spec, List<String> words, int wordIndex, int commandWords) {
    List<PositionalParamSpec> positionals = spec.positionalParameters();
    if (positionals == null || positionals.isEmpty()) {
      return null;
    }

    int positionalIndex = 0;
    for (int i = commandWords; i < wordIndex && i < words.size(); i++) {
      String token = words.get(i);
      if (token.startsWith("-")) {
        OptionSpec option = spec.findOption(token);
        if (option == null) {
          continue;
        }

        int max = option.arity().max();
        if (max == Integer.MAX_VALUE) {
          return null;
        }

        for (int consumed = 0; consumed < max && i + 1 < wordIndex; consumed++) {
          String next = words.get(i + 1);
          if (next.startsWith("-")) {
            break;
          }
          i++;
        }
        continue;
      }

      positionalIndex++;
    }

    int selectedIndex = Math.min(positionalIndex, positionals.size() - 1);
    PositionalParamSpec selected = positionals.get(selectedIndex);
    if (!selected.arity().isUnspecified() && positionalIndex >= positionals.size()
        && !selected.arity().isVariable()) {
      return null;
    }
    return selected;
  }

  private static ResolvedCommand resolveCommand(
      CommandSpec rootSpec, List<String> words, int wordIndex, String currentWord) {
    CommandSpec spec = rootSpec;
    int commandWords = 0;
    int limit = Math.min(wordIndex, words.size());

    for (int i = 0; i < limit && i < words.size(); i++) {
      String token = words.get(i);
      if (token.startsWith("-")) {
        break;
      }

      CommandLine sub = spec.subcommands().get(token);
      if (sub == null) {
        break;
      }

      spec = sub.getCommandSpec();
      commandWords = i + 1;
    }

    boolean completeSubcommands = !spec.subcommands().isEmpty()
        && !currentWord.startsWith("-") && wordIndex == commandWords;
    return new ResolvedCommand(spec, commandWords, completeSubcommands);
  }

  private static boolean isSourceFileContext(CommandSpec spec, int wordIndex, int commandWords,
      String currentWord) {
    return "source".equals(spec.name())
        && !currentWord.startsWith("-")
        && wordIndex == commandWords;
  }

  private static void addSubcommands(CommandSpec spec, List<Candidate> candidates) {
    for (String name : spec.subcommands().keySet()) {
      candidates.add(new Candidate(name));
    }
  }

  private static void addPositionalValues(
      CommandSpec spec, PositionalParamSpec positional, List<String> words, int wordIndex,
      String currentWord, List<Candidate> candidates) {
    Set<String> values = new LinkedHashSet<>();
    Class<?> completerClass = applyCompletionAnnotation(spec, positional,
        positional.userObject(), positional.getter(), words, wordIndex, values);

    if (completerClass == org.xipki.shell.completer.FilePathCompleter.class) {
      addPathCandidates(currentWord, "", candidates, false, false);
      return;
    } else if (completerClass == org.xipki.shell.completer.DirPathCompleter.class) {
      addPathCandidates(currentWord, "", candidates, true, false);
      return;
    }

    for (String value : values) {
      candidates.add(new Candidate(value));
    }
  }

  private static void addOptions(CommandSpec spec, List<Candidate> candidates) {
    for (OptionSpec option : spec.options()) {
      for (String name : option.names()) {
        candidates.add(new Candidate(name));
      }
    }
  }

  private static void addOptionValues(
      CommandSpec spec, OptionSpec option, List<String> words, int wordIndex,
      String currentWord, List<Candidate> candidates) {
    Set<String> values = new LinkedHashSet<>();
    String valuePrefix = completionValuePrefix(option, currentWord);

    Class<?> type = option.typeInfo().getType();
    if (type.isEnum()) {
      Object[] constants = type.getEnumConstants();
      if (constants != null) {
        for (Object constant : constants) {
          values.add(constant.toString());
          values.add(constant.toString().toLowerCase(Locale.ROOT));
        }
      }
    } else if (type == boolean.class || type == Boolean.class) {
      values.addAll(TRUE_FALSE);
    }

    Class<?> completerClass = applyCompletionAnnotation(spec, option, option.userObject(),
        option.getter(), words, wordIndex, values);

    if (completerClass == org.xipki.shell.completer.FilePathCompleter.class) {
      addPathCandidates(currentWord, valuePrefix, candidates, false, false);
    } else if (completerClass == org.xipki.shell.completer.DirPathCompleter.class) {
      addPathCandidates(currentWord, valuePrefix, candidates, true, false);
    }

    for (String value : values) {
      candidates.add(new Candidate(valuePrefix.isEmpty() ? value : valuePrefix + value));
    }
  }

  private static Class<?> applyCompletionAnnotation(
      CommandSpec commandSpec, ArgSpec argSpec, Object userObject,
      CommandLine.Model.IGetter getter, List<String> words,
      int wordIndex, Set<String> values) {
    try {
      java.lang.reflect.Field field = null;
      if (userObject instanceof java.lang.reflect.Field) {
        field = (java.lang.reflect.Field) userObject;
      } else if (getter != null) {
        try {
          java.lang.reflect.Field fGetter = getter.getClass().getDeclaredField("field");
          fGetter.setAccessible(true);
          field = (java.lang.reflect.Field) fGetter.get(getter);
        } catch (Exception ex) {
          // ignore inaccessible getter field metadata
        }
      }

      if (field != null && field.isAnnotationPresent(Completion.class)) {
        Completion comp = field.getAnnotation(Completion.class);
        for (String value : comp.values()) {
          if (value != null) {
            values.add(value);
          }
        }

        CompletionProvider completer = comp.value().getDeclaredConstructor().newInstance();
        Set<String> annotatedValues = completer.complete(commandSpec, argSpec, words, wordIndex);
        if (annotatedValues != null) {
          values.addAll(annotatedValues);
        }
        return comp.value();
      }
    } catch (Exception ex) {
      LOG.debug("Ignore Completion annotation error", ex);
    }
    return null;
  }

  private static String completionValuePrefix(OptionSpec option, String currentWord) {
    String text = currentWord == null ? "" : currentWord;
    if (option.splitRegex() == null || text.isEmpty()) {
      return "";
    }

    int idx = text.lastIndexOf(',');
    return idx == -1 ? "" : text.substring(0, idx + 1);
  }

  private static void addPathCandidates(String currentWord, String valuePrefix,
      List<Candidate> candidates, boolean directoriesOnly, boolean expandUniqueDir) {
    PathCompletionRequest request = PathCompletionRequest.forWord(currentWord, valuePrefix);
    if (request == null) {
      return;
    }

    Set<String> seen = new LinkedHashSet<>();
    for (Path candidateBaseDir : candidateBaseDirs(request.baseDir)) {
      try {
        if (!Files.isDirectory(candidateBaseDir)) {
          continue;
        }
        List<Path> matchingPaths = listMatchingPaths(candidateBaseDir, request.prefix);
        boolean expandedUniqueDir = false;
        if (expandUniqueDir && !request.prefix.isEmpty() && matchingPaths.size() == 1
            && Files.isDirectory(matchingPaths.get(0))) {
          addDirectoryChildren(request, candidateBaseDir, matchingPaths.get(0), candidates,
              seen, directoriesOnly);
          expandedUniqueDir = true;
        }

        if (!expandedUniqueDir) {
          for (Path path : matchingPaths) {
            addPathCandidate(request, path, candidates, seen, directoriesOnly);
          }
        }
      } catch (Exception ex) {
        // ignore completion failures
      }
    }
  }

  private static List<Path> listMatchingPaths(Path baseDir, String prefix) throws IOException {
    List<Path> paths = new ArrayList<>();
    try (var stream = Files.list(baseDir)) {
      stream.forEach(path -> {
        String name = path.getFileName().toString();
        if (prefix.isEmpty() || name.startsWith(prefix)) {
          paths.add(path);
        }
      });
    }
    return paths;
  }

  private static void addDirectoryChildren(PathCompletionRequest request, Path actualBaseDir,
      Path matchedDir, List<Candidate> candidates, Set<String> seen, boolean directoriesOnly)
      throws IOException {
    Path relativeDir = actualBaseDir.relativize(matchedDir);
    String displayDir = request.displayBase;
    for (Path segment : relativeDir) {
      displayDir = appendDisplaySegment(displayDir, segment.toString(), request.windowsStyle);
    }

    try (var stream = Files.list(matchedDir)) {
      String finalDisplayDir = displayDir;
      stream.forEach(path -> addPathCandidate(
          request.withDisplayBase(finalDisplayDir), path, candidates, seen, directoriesOnly));
    }
  }

  private static void addPathCandidate(PathCompletionRequest request, Path path,
      List<Candidate> candidates, Set<String> seen, boolean directoriesOnly) {
    if (directoriesOnly && !Files.isDirectory(path)) {
      return;
    }

    String name = path.getFileName().toString();
    String value = appendDisplaySegment(request.displayBase, name, request.windowsStyle);
    boolean isDirectory = Files.isDirectory(path);
    if (isDirectory) {
      value += request.windowsStyle ? "\\" : "/";
    }
    if (seen.add(value)) {
      String candidateValue = request.valuePrefix + request.filePrefix + value;
      candidates.add(new Candidate(candidateValue, candidateValue, null, null, null, null,
          !isDirectory));
    }
  }

  private static List<Path> candidateBaseDirs(Path requestedBaseDir) {
    List<Path> ret = new ArrayList<>();
    ret.add(requestedBaseDir);

    if (!requestedBaseDir.isAbsolute()) {
      Path shellHomeBase = ShellUtil.shellHome().resolve(requestedBaseDir).normalize();
      if (!shellHomeBase.equals(requestedBaseDir.normalize())) {
        ret.add(shellHomeBase);
      }
    }

    return ret;
  }

  private static String appendDisplaySegment(String displayBase, String name, boolean windowsStyle) {
    if (displayBase == null || displayBase.isEmpty() || ".".equals(displayBase)) {
      return name;
    }

    char separator = windowsStyle ? '\\' : '/';
    if (displayBase.charAt(displayBase.length() - 1) == separator) {
      return displayBase + name;
    }
    return displayBase + separator + name;
  }

  private static boolean isWindowsStylePath(String text) {
    if (text == null || text.isEmpty()) {
      return false;
    }
    return text.indexOf('\\') >= 0
        || text.startsWith("\\\\")
        || text.matches("^[A-Za-z]:(?:$|[\\\\/].*)");
  }

  private static int lastPathSeparator(String text, boolean windowsStyle) {
    int slashIdx = text.lastIndexOf('/');
    if (!windowsStyle) {
      return slashIdx;
    }
    return Math.max(slashIdx, text.lastIndexOf('\\'));
  }

  private static String trimTrailingSeparators(String text, boolean windowsStyle) {
    if (text == null || text.isEmpty()) {
      return "";
    }

    int end = text.length();
    while (end > 0) {
      char ch = text.charAt(end - 1);
      if (ch == '/' || (windowsStyle && ch == '\\')) {
        end--;
      } else {
        break;
      }
    }
    return text.substring(0, end);
  }

  private static String normalizeDisplayBase(String text, boolean windowsStyle) {
    if (text == null || text.isEmpty()) {
      return "";
    }

    if ("/".equals(text)) {
      return "/";
    }

    if (windowsStyle && text.matches("^[A-Za-z]:[\\\\/]$")) {
      return text.substring(0, 2) + "\\";
    }

    return trimTrailingSeparators(text, windowsStyle);
  }

  private static Path toLookupPath(String effectiveWord, boolean windowsStyle) {
    if (effectiveWord == null || effectiveWord.isEmpty()) {
      return Paths.get(".");
    }

    if (windowsStyle) {
      if (!WINDOWS_HOST && effectiveWord.startsWith("\\\\")) {
        return null;
      }
      return Paths.get(effectiveWord.replace('\\', File.separatorChar));
    }

    return Paths.get(effectiveWord);
  }

  private static final class PathCompletionRequest {

    private final String valuePrefix;

    private final String filePrefix;

    private final boolean windowsStyle;

    private final Path baseDir;

    private final String displayBase;

    private final String prefix;

    private PathCompletionRequest(String valuePrefix, String filePrefix, boolean windowsStyle,
        Path baseDir, String displayBase, String prefix) {
      this.valuePrefix = valuePrefix;
      this.filePrefix = filePrefix;
      this.windowsStyle = windowsStyle;
      this.baseDir = baseDir;
      this.displayBase = displayBase;
      this.prefix = prefix;
    }

    private static PathCompletionRequest forWord(String currentWord, String valuePrefix) {
      String effectiveWord = valuePrefix.isEmpty()
          ? currentWord
          : currentWord == null ? "" : currentWord.substring(valuePrefix.length());
      if (effectiveWord == null) {
        effectiveWord = "";
      }

      String filePrefix = "";
      if (effectiveWord.startsWith("file:")) {
        filePrefix = "file:";
        effectiveWord = effectiveWord.substring("file:".length());
      }

      boolean windowsStyle = isWindowsStylePath(effectiveWord);
      boolean homeRelative = "~".equals(effectiveWord)
          || effectiveWord.startsWith("~/")
          || effectiveWord.startsWith("~\\");
      String lookupWord = effectiveWord;
      if (homeRelative) {
        String userHome = System.getProperty("user.home", "");
        lookupWord = userHome + effectiveWord.substring(1);
      }

      Path typedPath = toLookupPath(lookupWord, windowsStyle);
      if (typedPath == null) {
        return null;
      }

      Path baseDir;
      String displayBase;
      String prefix;
      boolean endsWithSeparator = !effectiveWord.isEmpty()
          && (effectiveWord.endsWith("/") || (windowsStyle && effectiveWord.endsWith("\\")));
      if (effectiveWord.isEmpty()) {
        baseDir = Paths.get(".");
        displayBase = "";
        prefix = "";
      } else if (endsWithSeparator) {
        baseDir = typedPath;
        displayBase = normalizeDisplayBase(effectiveWord, windowsStyle);
        prefix = "";
      } else if (Files.isDirectory(typedPath)) {
        baseDir = typedPath;
        displayBase = effectiveWord;
        prefix = "";
      } else {
        Path shellHomeTypedPath = ShellUtil.shellHome().resolve(typedPath).normalize();
        if (!typedPath.isAbsolute() && Files.isDirectory(shellHomeTypedPath)) {
          baseDir = typedPath;
          displayBase = effectiveWord;
          prefix = "";
        } else {
          Path parent = typedPath.getParent();
          baseDir = parent == null ? Paths.get(".") : parent;

          int separatorIdx = lastPathSeparator(effectiveWord, windowsStyle);
          if (separatorIdx == -1) {
            displayBase = "";
            prefix = effectiveWord;
          } else {
            displayBase = normalizeDisplayBase(effectiveWord.substring(0, separatorIdx + 1),
                windowsStyle);
            prefix = effectiveWord.substring(separatorIdx + 1);
          }
        }
      }

      return new PathCompletionRequest(valuePrefix, filePrefix, windowsStyle, baseDir,
          displayBase, prefix);
    }

    private PathCompletionRequest withDisplayBase(String newDisplayBase) {
      return new PathCompletionRequest(valuePrefix, filePrefix, windowsStyle, baseDir,
          newDisplayBase, prefix);
    }
  }

  private static final class ResolvedCommand {

    private final CommandSpec spec;

    private final int commandWords;

    private final boolean completeSubcommands;

    private ResolvedCommand(CommandSpec spec, int commandWords, boolean completeSubcommands) {
      this.spec = spec;
      this.commandWords = commandWords;
      this.completeSubcommands = completeSubcommands;
    }
  }

}
