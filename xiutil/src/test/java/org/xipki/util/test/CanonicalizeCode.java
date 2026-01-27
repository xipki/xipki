// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Canonicalize the text files.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CanonicalizeCode {
  private static final int MAX_COUNT_IN_LINE = 80;

  private static final Set<String> textFileExtensions = new HashSet<>(
          Arrays.asList("txt", "xml", "xsd", "cfg", "properties",
              "script", "jxb", "info"));

  private static final Set<String> excludeTextFiles = new HashSet<>();

  private final String baseDir;

  private final int baseDirLen;

  private CanonicalizeCode(String baseDir) {
    baseDir = IoUtil.expandFilepath(baseDir);
    this.baseDir = baseDir.endsWith(File.separator) ? baseDir
        : baseDir + File.separator;
    this.baseDirLen = this.baseDir.length();
  }

  public static void main(String[] args) {
    args = new String[] {"/Users/liao/source/xipki/xipki/"};
    for (String arg : args) {
      try {
        System.out.println("Canonicalize dir " + arg);
        CanonicalizeCode canonicalizer = new CanonicalizeCode(arg);
        canonicalizer.canonicalize();
        canonicalizer.checkWarnings();
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }
  }

  private void canonicalize() throws Exception {
    canonicalizeDir(new File(baseDir), true);
  }

  private void canonicalizeDir(File dir, boolean root) throws Exception {
    if (dir.getName().equals(".idea")) {
      return;
    }

    if (!root) {
      // skip git submodules
      if (new File(dir, ".git").exists()) {
        return;
      }
    }

    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      String filename = file.getName();
      if (file.isDirectory()) {
        if (!"target".equals(filename) && !"tbd".equals(filename)) {
          canonicalizeDir(file, false);
        }
      } else {
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1) ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension) || "c".equalsIgnoreCase(extension)) {
          canonicalizeFile(file);
        } else if (textFileExtensions.contains(extension)
            && !excludeTextFiles.contains(filename)) {
          try {
            canonicalizeTextFile(file);
          } catch (Exception ex) {
            System.err.println("could not canonicalize file " + file);
            ex.printStackTrace();
          }
        }
      }
    }
  } // method canonicalizeDir

  private void canonicalizeFile(File file) throws Exception {
    byte[] newLine = detectNewline(file);

    byte[] newBytes;
    try (BufferedReader reader = Files.newBufferedReader(file.toPath());
         ByteArrayOutputStream writer = new ByteArrayOutputStream()){
      String line;
      boolean lastLineEmpty = false;

      while ((line = reader.readLine()) != null) {
        String canonicalizedLine = canonicalizeLine(line, new String(newLine));
        boolean addThisLine = true;
        if (canonicalizedLine.isEmpty()) {
          if (!lastLineEmpty) {
            lastLineEmpty = true;
          } else {
            addThisLine = false;
          }
        } else {
          lastLineEmpty = false;
        }

        if (addThisLine) {
          writeLine(writer, newLine, canonicalizedLine);
        }
      } // end while

      newBytes = writer.toByteArray();
    }

    byte[] oldBytes = IoUtil.read(file);

    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      IoUtil.save(newFile, newBytes);
      IoUtil.renameTo(newFile, file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeFile

  private void canonicalizeTextFile(File file) throws Exception {
    byte[] newLine = new byte[]{'\n'};

    byte[] newBytes;
    try (BufferedReader reader = Files.newBufferedReader(file.toPath());
         ByteArrayOutputStream writer = new ByteArrayOutputStream()) {
      String line;
      while ((line = reader.readLine()) != null) {
        String canonicalizedLine = canonicalizeTextLine(line);
        writeLine(writer, newLine, canonicalizedLine);
      } // end while

      newBytes = writer.toByteArray();
    }

    byte[] oldBytes = IoUtil.read(file);
    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      IoUtil.save(newFile, newBytes);
      IoUtil.renameTo(newFile, file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeTextFile

  private void checkWarnings() throws Exception {
    int n = checkWarningsInDir(new File(baseDir), true);
    System.out.println("# Files with warnings: " + n);
  }

  private int checkWarningsInDir(File dir, boolean root) throws Exception {
    if (!root) {
      // skip git submodules
      if (new File(dir, ".git").exists()) {
        return 0;
      }
    }

    File[] files = dir.listFiles();
    if (files == null) {
      return 0;
    }

    int n = 0;
    for (File file : files) {
      if (file.isDirectory()) {
        if (!file.getName().equals("target")
            && !file.getName().equals("tbd")) {
          n += checkWarningsInDir(file, false);
        }
      } else {
        String filename = file.getName();
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1) ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          if (checkWarningsInFile(file)) {
            n++;
          }
        }
      }
    }

    return n;
  } // method checkWarningsInDir

  private boolean checkWarningsInFile(File file) throws Exception {
    if (file.getName().equals("package-info.java")) {
      return false;
    }

    BufferedReader reader = Files.newBufferedReader(file.toPath());

    boolean authorsLineAvailable = false;
    boolean licenseHeaderAvailable = false;

    List<Integer> lineNumbers = new LinkedList<>();

    int lineNumber = 0;
    try {
      String line;

      while ((line = reader.readLine()) != null) {
        if (lineNumber == 0) {
          licenseHeaderAvailable = !line.startsWith("package");
        }

        lineNumber++;
        if (lineNumber == 1 && line.startsWith("// #THIRDPARTY")) {
          return false;
        }

        if (!authorsLineAvailable && line.contains("* @author")) {
          authorsLineAvailable = true;
        }

        if (line.length() > MAX_COUNT_IN_LINE &&
            !(line.contains("http://") || line.contains("https://"))
            && !line.contains("import ")) {
          lineNumbers.add(lineNumber);
        }
      } // end while
    } finally {
      reader.close();
    }

    boolean withWarnings = false;
    if (!lineNumbers.isEmpty()) {
      System.out.println("Please check file " +
          file.getPath().substring(baseDirLen) + ": lines " +
          Arrays.toString(lineNumbers.toArray(new Integer[0])));
      withWarnings = true;
    }

    if (!licenseHeaderAvailable) {
      System.out.println("Please check file " +
          file.getPath().substring(baseDirLen) + ": no license header");
      withWarnings = true;
    }

    if (!authorsLineAvailable) {
      System.out.println("Please check file " +
          file.getPath().substring(baseDirLen) + ": no authors line");
      withWarnings = true;
    }
    return withWarnings;
  } // method checkWarningsInFile

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeLine(String line, String newLine) {
    if (line.trim().startsWith("//")) {
      // comments
      String nline = line.replace("\t", "    ");
      return removeTrailingSpaces(nline);
    }

    StringBuilder sb = new StringBuilder();
    int len = line.length();

    int lastNonSpaceCharIndex = 0;
    int index = 0;
    for (int i = 0; i < len; i++) {
      char ch = line.charAt(i);
      if (ch == '\t') {
        sb.append("    ");
        index += 4;
      } else if (ch == ' ') {
        sb.append(ch);
        index++;
      } else {
        sb.append(ch);
        index++;
        lastNonSpaceCharIndex = index;
      }
    }

    int numSpacesAtEnd = sb.length() - lastNonSpaceCharIndex;
    if (numSpacesAtEnd > 0) {
      sb.delete(lastNonSpaceCharIndex, sb.length());
    }

    String ret = sb.toString();
    // If too long
    if (ret.length() > MAX_COUNT_IN_LINE) {
      int idx = ret.indexOf(" throws ");
      if (idx != -1) {
        String before = ret.substring(0, idx);
        if (!before.trim().isEmpty()) {
          String after = ret.substring(idx + 1);
          int leadingSpaces = 0;
          for (int i = 0; i < before.length(); i++)
            if (before.charAt(i) == ' ') {
              leadingSpaces++;
            } else {
              break;
            }
          ret = before + newLine + " ".repeat(leadingSpaces + 4) + after;
        }
      }
    }

    return ret;
  } // end canonicalizeLine

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeTextLine(String line) {
    return removeTrailingSpaces(line).replaceAll("\t", "  ");
  }

  private static String removeTrailingSpaces(String line) {
    final int n = line.length();
    int idx;
    for (idx = n - 1; idx >= 0; idx--) {
      char ch = line.charAt(idx);
      if (ch != ' ') {
        break;
      }
    }
    return (idx == n - 1) ?  line : line.substring(0, idx + 1);
  } // method removeTrailingSpaces

  private static byte[] detectNewline(File file) throws IOException {
    try (InputStream is = Files.newInputStream(file.toPath())) {
      byte[] bytes = new byte[200];
      int size;
      try {
        size = is.read(bytes);
      } finally {
        is.close();
      }

      for (int i = 0; i < size - 1; i++) {
        byte bb = bytes[i];
        if (bb == '\n') {
          return new byte[]{'\n'};
        } else if (bb == '\r') {
          if (bytes[i + 1] == '\n') {
            return new byte[]{'\r', '\n'};
          } else {
            return new byte[]{'\r'};
          }
        }
      }

      return new byte[]{'\n'};
    }
  }

  private static void writeLine(OutputStream out, byte[] newLine, String line)
      throws IOException {
    if (StringUtil.isNotBlank(line)) {
      out.write(StringUtil.toUtf8Bytes(line));
    }
    out.write(newLine);
  }

}
