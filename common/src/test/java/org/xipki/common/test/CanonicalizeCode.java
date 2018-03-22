/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.common.test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;

/**
 * Canonicalize the text files.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CanonicalizeCode {

  private static final List<byte[]> headerLines = new ArrayList<>(20);

  private static final Set<String> textFileExtensions =
      new HashSet<>(Arrays.asList("txt", "xml", "xsd", "cfg", "properties",
          "script", "xml-template", "script-template", "jxb", "info",
          "properties-db2", "properties-h2", "properties-hsqldb", "properties-mariadb",
          "properties-mysql", "properties-pgsql", "properties-oracle"));

  private static final Set<String> excludeTextFiles =
      new HashSet<>(Arrays.asList("draft-gutmann-scep-00.txt"));

  private static Throwable initializationError;

  private final String baseDir;

  private final int baseDirLen;

  static {
    try {
      BufferedReader reader = new BufferedReader(new FileReader("src/test/resources/HEADER.txt"));
      String line;
      while ((line = reader.readLine()) != null) {
        headerLines.add(line.getBytes("utf-8"));
      }
      reader.close();
    } catch (Throwable th) {
      initializationError = th;
    }
  }

  private CanonicalizeCode(String baseDir) {
    this.baseDir = baseDir.endsWith(File.separator) ? baseDir : baseDir + File.separator;
    this.baseDirLen = this.baseDir.length();
  }

  public static void main(String[] args) {
    if (initializationError != null) {
      initializationError.printStackTrace();
      return;
    }

    for (String arg : args) {
      try {
        String baseDir = arg;
        System.out.println("Canonicalize dir " + baseDir);
        CanonicalizeCode canonicalizer = new CanonicalizeCode(baseDir);
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

        if ("java".equals(extension)) {
          canonicalizeFile(file);
        } else if (textFileExtensions.contains(extension) && !excludeTextFiles.contains(filename)) {
          canonicalizeTextFile(file);
        }
      }
    }
  } // method canonicalizeDir

  private void canonicalizeFile(File file) throws Exception {
    byte[] newLine = detectNewline(file);

    BufferedReader reader = new BufferedReader(new FileReader(file));

    ByteArrayOutputStream writer = new ByteArrayOutputStream();

    try {
      String line;
      boolean skip = true;
      boolean lastLineEmpty = false;
      boolean licenseTextAdded = false;
      boolean thirdparty = false;
      int lineNumber = 0;

      while ((line = reader.readLine()) != null) {
        if (lineNumber == 0 && line.startsWith("// #THIRDPARTY#")) {
          thirdparty = true;
          skip = false;
        }
        lineNumber++;

        if (line.trim().startsWith("package ") || line.trim().startsWith("import ")) {
          if (!licenseTextAdded) {
            if (!thirdparty) {
              writeLicenseHeader(writer, newLine);
            }
            licenseTextAdded = true;
          }
          skip = false;
        }

        if (skip) {
          continue;
        }

        String canonicalizedLine = canonicalizeLine(line);
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
    } finally {
      writer.close();
      reader.close();
    }

    byte[] oldBytes = IoUtil.read(file);
    byte[] newBytes = writer.toByteArray();
    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      IoUtil.save(file, newBytes);
      newFile.renameTo(file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeFile

  private void canonicalizeTextFile(File file) throws Exception {
    byte[] newLine = new byte[]{'\n'};
    BufferedReader reader = new BufferedReader(new FileReader(file));
    ByteArrayOutputStream writer = new ByteArrayOutputStream();

    try {
      String line;
      while ((line = reader.readLine()) != null) {
        String canonicalizedLine = canonicalizeTextLine(line);
        writeLine(writer, newLine, canonicalizedLine);
      } // end while
    } finally {
      writer.close();
      reader.close();
    }

    byte[] oldBytes = IoUtil.read(file);
    byte[] newBytes = writer.toByteArray();
    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      IoUtil.save(file, newBytes);
      newFile.renameTo(file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeTextFile

  private void checkWarnings() throws Exception {
    checkWarningsInDir(new File(baseDir), true);
  }

  private void checkWarningsInDir(File dir, boolean root) throws Exception {
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
      if (file.isDirectory()) {
        if (!file.getName().equals("target")
            && !file.getName().equals("tbd")) {
          checkWarningsInDir(file, false);
        }

        continue;
      } else {
        String filename = file.getName();
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1) ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          checkWarningsInFile(file);
        }
      }
    }
  } // method checkWarningsInDir

  private void checkWarningsInFile(File file) throws Exception {
    if (file.getName().equals("package-info.java")) {
      return;
    }

    BufferedReader reader = new BufferedReader(new FileReader(file));

    boolean authorsLineAvailable = false;
    boolean thirdparty = false;

    List<Integer> lineNumbers = new LinkedList<>();

    int lineNumber = 0;
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        lineNumber++;
        if (lineNumber == 1 && line.startsWith("// #THIRDPARTY")) {
          return;
        }

        if (!authorsLineAvailable && line.contains("* @author")) {
          authorsLineAvailable = true;
        }

        if (line.length() > 100 && !line.contains("http")) {
          lineNumbers.add(lineNumber);
        }
      } // end while
    } finally {
      reader.close();
    }

    if (!lineNumbers.isEmpty()) {
      System.out.println("Please check file " + file.getPath().substring(baseDirLen)
          + ": lines " + Arrays.toString(lineNumbers.toArray(new Integer[0])));
    }

    if (!authorsLineAvailable && !thirdparty) {
      System.out.println("Please check file " + file.getPath().substring(baseDirLen)
          + ": no authors line");
    }
  } // method checkWarningsInFile

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeLine(String line) {
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

    return sb.toString();
  } // end canonicalizeLine

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeTextLine(String line) {
    return removeTrailingSpaces(line).replaceAll("\t", "  ");
  } // end canonicalizeTextLine

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
    InputStream is = new FileInputStream(file);
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

  private static void writeLicenseHeader(OutputStream out, byte[] newLine) throws IOException {
    for (byte[] line : headerLines) {
      if (line.length > 0) {
        out.write(line);
      }
      out.write(newLine);
    }
    out.write(newLine);
  }

  private static void writeLine(OutputStream out, byte[] newLine, String line) throws IOException {
    if (StringUtil.isNotBlank(line)) {
      out.write(line.getBytes());
    }
    out.write(newLine);
  }

}
