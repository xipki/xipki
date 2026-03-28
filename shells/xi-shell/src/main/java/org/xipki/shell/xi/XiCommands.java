// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.DirPathCompleter;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.http.Curl;
import org.xipki.util.extra.http.Curl.CurlResult;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.io.FileUtils;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * The utility shell.
 *
 * @author Lijun Liao (xipki)
 */

class XiCommands {
  abstract static class XiCommand extends ShellBaseCommand {

    protected String expand(String path) {
      return IoUtil.expandFilepath(path);
    }
  }

  @Command(name = "uppercase", description = "convert to uppercase string",
      mixinStandardHelpOptions = true)
  static class Uppercase extends ShellBaseCommand {

    @Parameters(index = "0", description = "text to be converted")
    private String text;

    @Override
    public void run() {
      println(text.toUpperCase(Locale.ROOT));
    }
  }

  @Command(name = "lowercase", description = "convert to lowercase string",
      mixinStandardHelpOptions = true)
  static class Lowercase extends ShellBaseCommand {

    @Parameters(index = "0", description = "text to be converted")
    private String text;

    @Override
    public void run() {
      println(text.toLowerCase(Locale.ROOT));
    }
  }

  @Command(name = "confirm", description = "confirm an action", mixinStandardHelpOptions = true)
  static class Confirm extends XiCommand {

    @Parameters(index = "0", description = "prompt message")
    private String prompt;

    @Override
    public void run() {
      try {
        if (!confirmAction(prompt + "\nDo you want to continue")) {
          throw new RuntimeException("User cancelled");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "copy-dir", description = "copy content of the directory to destination",
      mixinStandardHelpOptions = true)
  static class CopyDir extends XiCommand {

    @Parameters(index = "0", description = "content of this directory will be copied")
    @Completion(DirPathCompleter.class)
    private String source;

    @Parameters(index = "1", description = "destination directory")
    @Completion(DirPathCompleter.class)
    private String dest;

    @Override
    public void run() {
      try {
        File sourceDir = new File(expand(source));
        if (!sourceDir.exists()) {
          throw new IllegalArgumentException(source + " does not exist");
        }
        if (!sourceDir.isDirectory()) {
          throw new IllegalArgumentException(source + " is not a directory");
        }

        File destDir = new File(expand(dest));
        IoUtil.mkdirs(destDir);
        FileUtils.copyDirectory(sourceDir, destDir);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "copy-file", description = "copy file", mixinStandardHelpOptions = true)
  static class CopyFile extends XiCommand {

    @Parameters(arity = "2..*", description = "sources followed by destination")
    @Completion(FilePathCompleter.class)
    private List<String> files;

    @Option(names = {"--force", "-f"}, description = "override existing file, never prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        int n = files.size();
        String dest = expand(files.get(n - 1));
        File destObj = new File(dest);
        boolean destExists = destObj.exists();
        boolean isDestDir;
        if (destExists) {
          isDestDir = destObj.isDirectory();
        } else if (n > 2) {
          isDestDir = true;
        } else {
          char c = dest.charAt(dest.length() - 1);
          isDestDir = c == '\\' || c == '/';
        }

        if (n > 2 && !isDestDir) {
          throw new IllegalArgumentException(dest + " is not a folder");
        }

        List<File> sourceFiles = new ArrayList<>(n - 1);
        for (int i = 0; i < n - 1; i++) {
          File sourceFile = new File(expand(files.get(i)));
          if (!sourceFile.exists()) {
            throw new IllegalArgumentException(sourceFile + " does not exist");
          }
          if (!sourceFile.isFile()) {
            throw new IllegalArgumentException(sourceFile + " is not a file");
          }
          sourceFiles.add(sourceFile);
        }

        if (isDestDir) {
          for (File sourceFile : sourceFiles) {
            copyOne(sourceFile, new File(dest, sourceFile.getName()));
          }
        } else {
          copyOne(sourceFiles.get(0), new File(dest));
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private void copyOne(File sourceFile, File destFile) throws Exception {
      if (destFile.exists()) {
        if (!destFile.isFile()) {
          throw new IllegalArgumentException("cannot override an existing directory by a file");
        }
        if (!force && !confirmAction("Do you want to override the file " + destFile.getPath())) {
          return;
        }
      } else {
        IoUtil.mkdirsParent(destFile.toPath());
      }

      FileUtils.copyFile(sourceFile, destFile, true);
    }
  }

  @Command(name = "file-exists", description = "test whether file or folder exists",
      mixinStandardHelpOptions = true)
  static class FileExists extends XiCommand {

    @Parameters(index = "0", description = "file or dir to be checked")
    @Completion(FilePathCompleter.class)
    private String target;

    @Override
    public void run() {
      println(Boolean.toString(new File(expand(target)).exists()));
    }
  }

  @Command(name = "base64", description = "Base64 encode / decode", mixinStandardHelpOptions = true)
  static class Base64EnDecode extends XiCommand {

    @Option(names = {"--decode", "-d"}, description = "decode")
    private boolean decode;

    @Parameters(index = "0", description = "source file")
    @Completion(FilePathCompleter.class)
    private String source;

    @Parameters(index = "1", description = "destination file")
    @Completion(FilePathCompleter.class)
    private String dest;

    @Override
    public void run() {
      try {
        File sourceFile = new File(expand(source));
        if (!sourceFile.exists()) {
          throw new IllegalArgumentException(source + " does not exist");
        }
        if (!sourceFile.isFile()) {
          throw new IllegalArgumentException(source + " is not a file");
        }

        byte[] sourceBytes = IoUtil.read(sourceFile);
        byte[] targetBytes = decode ? Base64.decode(sourceBytes)
            : Base64.encodeToByte(sourceBytes, true);
        IoUtil.save(expand(dest), targetBytes);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "curl", description = "transfer a URL", mixinStandardHelpOptions = true)
  static class CurlCommand extends XiCommand {

    @Parameters(index = "0", description = "URL")
    private String url;

    @Option(names = {"--verbose", "-v"}, description = "show request and response verbosely")
    private boolean verbose;

    @Option(names = {"--post", "-p"}, description = "send the request via HTTP POST")
    private boolean usePost;

    @Option(names = {"--data", "-d"}, description = "POST data")
    private String postData;

    @Option(names = {"--data-charset", "-c"}, description = "charset of data")
    private String postDataCharSet = "UTF-8";

    @Option(names = "--data-file", description = "file containing POST data")
    @Completion(FilePathCompleter.class)
    private String postDataFile;

    @Option(names = "--out", description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(names = {"--header", "-h"}, arity = "1", description = "header in request")
    private List<String> headers;

    @Option(names = {"--user", "-u"}, description = "user:password")
    private String userPassword;

    @Option(names = "--base64", description = "Base64-encode the content")
    private boolean base64;

    @Override
    public void run() {
      try {
        byte[] content = null;
        if (postData != null) {
          content = postData.getBytes(postDataCharSet);
        } else if (postDataFile != null) {
          content = IoUtil.read(postDataFile);
        }

        if (content != null) {
          usePost = true;
        }

        Map<String, String> headerNameValues = base64 || headers != null ? new HashMap<>() : null;
        if (headers != null) {
          for (String header : headers) {
            int idx = header.indexOf(':');
            if (idx == -1 || idx == header.length() - 1) {
              throw new IllegalArgumentException("invalid HTTP header: '" + header + "'");
            }
            headerNameValues.put(header.substring(0, idx), header.substring(idx + 1).trim());
          }
        }

        if (base64) {
          headerNameValues.put("Content-Transfer-Encoding", "base64");
          if (content != null) {
            content = Base64.encodeToByte(content, true);
          }
        }

        Curl curl = CurlRuntime.get();
        CurlResult result = usePost
            ? curl.curlPost(url, verbose, headerNameValues, userPassword, content)
            : curl.curlGet(url, verbose, headerNameValues, userPassword);

        if (result.content() == null && result.errorContent() == null) {
          println("NO response content");
        } else if (outFile != null) {
          if (result.content() != null) {
            saveVerbose("saved response to file", outFile, result.content());
          } else {
            saveVerbose("saved (error) response to file", "error-" + outFile,
                result.errorContent());
          }
        } else {
          String charset = getCharset(result.contentType());
          charset = charset == null ? "UTF-8" : charset;
          if (result.content() != null) {
            println(new String(result.content(), charset));
          } else {
            println("ERROR:");
            println(new String(result.errorContent(), charset));
          }
        }

        if (result.statusCode() != HttpStatusCode.SC_OK) {
          throw new RuntimeException("Received status code other than OK: " + result.statusCode());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private static String getCharset(String contentType) {
      if (StringUtil.isBlank(contentType) || contentType.indexOf(';') == -1) {
        return null;
      }

      StringTokenizer st = new StringTokenizer(contentType, ";");
      st.nextToken();
      while (st.hasMoreTokens()) {
        String token = st.nextToken();
        int idx = token.indexOf('=');
        if (idx != -1 && "charset".equalsIgnoreCase(token.substring(0, idx).trim())) {
          return token.substring(idx + 1);
        }
      }
      return null;
    }
  }

  @Command(name = "mkdir", description = "make directories", mixinStandardHelpOptions = true)
  static class Mkdir extends XiCommand {

    @Parameters(index = "0", description = "directory to be created")
    @Completion(DirPathCompleter.class)
    private String dirName;

    @Override
    public void run() {
      try {
        IoUtil.mkdirs(new File(expand(dirName)));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "move-dir", description = "move content of the directory to destination",
      mixinStandardHelpOptions = true)
  static class MoveDir extends XiCommand {

    @Parameters(index = "0", description = "content of this directory will be copied")
    @Completion(DirPathCompleter.class)
    private String source;

    @Parameters(index = "1", description = "destination directory")
    @Completion(DirPathCompleter.class)
    private String dest;

    @Override
    public void run() {
      try {
        File sourceDir = new File(expand(source));
        if (!sourceDir.exists()) {
          throw new IllegalArgumentException(source + " does not exist");
        }
        if (!sourceDir.isDirectory()) {
          throw new IllegalArgumentException(source + " is not a directory");
        }

        File destDir = new File(expand(dest));
        if (destDir.exists()) {
          if (!destDir.isDirectory()) {
            throw new IllegalArgumentException(dest + " is not a directory");
          }
        } else {
          IoUtil.mkdirs(destDir);
        }

        FileUtils.copyDirectory(sourceDir, destDir);
        FileUtils.deleteDirectory(sourceDir);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "move-file", description = "move file", mixinStandardHelpOptions = true)
  static class MoveFile extends XiCommand {

    @Parameters(index = "0", description = "file to be moved")
    @Completion(FilePathCompleter.class)
    private String source;

    @Parameters(index = "1", description = "destination file")
    @Completion(FilePathCompleter.class)
    private String dest;

    @Option(names = {"--force", "-f"}, description = "override existing file, never prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        File sourceFile = new File(expand(source));
        if (!sourceFile.exists()) {
          throw new IllegalArgumentException(source + " does not exist");
        }
        if (!sourceFile.isFile()) {
          throw new IllegalArgumentException(source + " is not a file");
        }

        File destFile = new File(expand(dest));
        if (destFile.exists()) {
          if (!destFile.isFile()) {
            throw new IllegalArgumentException("cannot override an existing directory by a file");
          }
          if (!force && !confirmAction("Do you want to override the file " + dest)) {
            return;
          }
        } else {
          IoUtil.mkdirsParent(destFile.toPath());
        }

        FileUtils.copyFile(sourceFile, destFile, true);
        IoUtil.deleteFile0(sourceFile);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "replace", description = "replace text in file", mixinStandardHelpOptions = true)
  static class Replace extends XiCommand {

    @Parameters(arity = "1..*", description = "files to be replaced")
    @Completion(FilePathCompleter.class)
    private List<String> sources;

    @Option(names = "--old", required = true, description = "text to be replaced")
    private List<String> oldTexts;

    @Option(names = "--new", required = true, description = "new text")
    private List<String> newTexts;

    @Override
    public void run() {
      try {
        Args.notNull(oldTexts, "oldTexts");
        Args.notNull(newTexts, "newTexts");
        if (oldTexts.size() != newTexts.size()) {
          throw new IllegalArgumentException("old.size != new.size");
        }

        for (String source : sources) {
          File sourceFile = new File(expand(source));
          if (!sourceFile.exists() || !sourceFile.isFile()) {
            continue;
          }
          replaceFile(sourceFile, oldTexts, newTexts);
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private void replaceFile(File file, List<String> oldTexts, List<String> newTexts)
        throws Exception {
      boolean changed = false;
      byte[] newBytes = null;
      try (BufferedReader reader = Files.newBufferedReader(file.toPath());
           ByteArrayOutputStream writer = new ByteArrayOutputStream()) {
        String line;
        while ((line = reader.readLine()) != null) {
          String origLine = line;
          for (int i = 0; i < oldTexts.size(); i++) {
            String old = oldTexts.get(i);
            if (line.contains(old)) {
              line = line.replace(old, newTexts.get(i));
            }
          }
          writer.write(StringUtil.toUtf8Bytes(line));
          writer.write('\n');
          if (!line.equals(origLine)) {
            changed = true;
          }
        }
        if (changed) {
          newBytes = writer.toByteArray();
        }
      }

      if (changed) {
        IoUtil.save(file, newBytes);
      }
    }
  }

  @Command(name = "rm", description = "remove file or directory", mixinStandardHelpOptions = true)
  static class Rm extends XiCommand {

    @Parameters(arity = "1..*", description = "files and directories to be deleted")
    @Completion(FilePathCompleter.class)
    private List<String> targetPaths;

    @Option(names = {"--recursive", "-r"}, description = "remove directories recursively")
    private boolean recursive;

    @Option(names = {"--force", "-f"}, description = "remove without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        for (String targetPath : targetPaths) {
          File target = new File(expand(targetPath));
          if (!target.exists()) {
            continue;
          }
          if (target.isDirectory()) {
            if (!recursive) {
              println("Please use option --recursive to delete directory");
              return;
            }
            if (force || confirmAction("Do you want to remove directory " + targetPath)) {
              FileUtils.deleteDirectory(target);
              println("removed directory " + targetPath);
            }
          } else if (force || confirmAction("Do you want to remove file " + targetPath)) {
            IoUtil.deleteFile0(target);
            println("removed file " + targetPath);
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "datetime", description = "get current date-time",
      mixinStandardHelpOptions = true)
  static class DateTime extends ShellBaseCommand {

    @Parameters(index = "0", arity = "0..1", description = "format")
    private String format = "yyyyMMdd-HHmmss";

    @Override
    public void run() {
      println(new SimpleDateFormat(format).format(Instant.now().toEpochMilli()));
    }
  }

  @Command(name = "osinfo", description = "get info of operating system",
      mixinStandardHelpOptions = true)
  static class OsInfo extends ShellBaseCommand {

    @Option(names = {"--name", "-n"}, description = "output OS name")
    private Boolean printName;

    @Option(names = {"--arch", "-a"}, description = "output OS arch")
    private Boolean printArch;

    @Override
    public void run() {
      String name = System.getProperty("os.name").toLowerCase(Locale.ROOT);
      name = name.startsWith("windows") ? "windows"
          : name.startsWith("linux") ? "linux"
          : name.startsWith("mac os x") ? "macosx" : name;

      String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
      boolean bName = Boolean.TRUE.equals(printName);
      boolean bArch = Boolean.TRUE.equals(printArch);
      if (printName == null && printArch == null) {
        println(name + "/" + arch);
      } else if (bName && bArch) {
        println(name + "/" + arch);
      } else if (bName) {
        println(name);
      } else if (bArch) {
        println(arch);
      } else {
        println("");
      }
    }
  }

  @Command(name = "exec", description = "execute terminal command", mixinStandardHelpOptions = true)
  static class ExecTerminalCommand extends XiCommand {

    @Parameters(index = "0", description = "Terminal command")
    private String command;

    @Option(names = "--ignore-error", description = "ignore non-zero exit")
    private boolean ignoreError;

    @Option(names = "--env", description = "environment variables")
    private String[] envs;

    @Option(names = {"--working-dir", "-w"}, description = "working directory")
    @Completion(DirPathCompleter.class)
    private String workingDir;

    @Override
    public void run() {
      try {
        List<String> args = splitCommand(IoUtil.expandFilepath(command, false));
        ProcessBuilder pb = new ProcessBuilder(args);
        if (envs != null) {
          for (String env : envs) {
            int idx = env.indexOf('=');
            if (idx > 0) {
              String value = env.substring(idx + 1);
              if (value.contains("~/")) {
                value = IoUtil.expandFilepath(value);
              }
              pb.environment().put(env.substring(0, idx), value);
            }
          }
        }
        if (workingDir != null) {
          pb.directory(new File(expand(workingDir)));
        }

        Process process = pb.start();
        int status = process.waitFor();
        System.out.write(IoUtil.readAllBytes(process.getInputStream()));
        if (status != 0) {
          System.err.write(IoUtil.readAllBytes(process.getErrorStream()));
          if (!ignoreError) {
            throw new RuntimeException("process exited with status " + status);
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private static List<String> splitCommand(String command) {
      List<String> tokens = new ArrayList<>();
      StringBuilder current = new StringBuilder();
      boolean inSingle = false;
      boolean inDouble = false;
      for (int i = 0; i < command.length(); i++) {
        char ch = command.charAt(i);
        if (ch == '\'' && !inDouble) {
          inSingle = !inSingle;
        } else if (ch == '"' && !inSingle) {
          inDouble = !inDouble;
        } else if (Character.isWhitespace(ch) && !inSingle && !inDouble) {
          if (current.length() > 0) {
            tokens.add(current.toString());
            current.setLength(0);
          }
        } else {
          current.append(ch);
        }
      }
      if (current.length() > 0) {
        tokens.add(current.toString());
      }
      return tokens;
    }
  }
}
