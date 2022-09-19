/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.util.Args;
import org.xipki.util.Curl.CurlResult;
import org.xipki.util.FileUtils;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Basic actions.
 *
 * @author Lijun Liao
 *
 */
public class Actions {

  @Command(scope = "xi", name = "confirm", description = "confirm an action")
  @Service
  public static class Confirm extends XiAction {

    @Argument(index = 0, name = "message", required = true, description = "prompt message")
    private String prompt;

    @Override
    protected Object execute0()
        throws Exception {
      boolean toContinue = confirm(prompt + "\nDo you want to continue", 3);
      if (!toContinue) {
        throw new CmdFailure("User cancelled");
      }

      return null;
    }

  } // class Confirm

  @Command(scope = "xi", name = "copy-dir",
      description = "copy content of the directory to destination")
  @Service
  public static class CopyDir extends XiAction {

    @Argument(index = 0, name = "source", required = true,
        description = "content of this directory will be copied")
    @Completion(Completers.DirCompleter.class)
    private String source;

    @Argument(index = 1, name = "destination", required = true,
        description = "destination directory")
    @Completion(Completers.DirCompleter.class)
    private String dest;

    @Override
    protected Object execute0()
        throws Exception {
      source = expandFilepath(source);
      dest = expandFilepath(dest);

      File sourceDir = new File(source);
      if (!sourceDir.exists()) {
        throw new IllegalCmdParamException(source + " does not exist");
      }

      if (!sourceDir.isDirectory()) {
        throw new IllegalCmdParamException(source + " is not a directory");
      }

      File destDir = new File(dest);
      if (destDir.exists()) {
        if (destDir.isFile()) {
          throw new IllegalCmdParamException(dest + " is not a directory");
        }
      } else {
        destDir.mkdirs();
      }

      FileUtils.copyDirectory(sourceDir, destDir);

      return null;
    }

  } // class CopyDir

  @Command(scope = "xi", name = "copy-file", description = "copy file")
  @Service
  public static class CopyFile extends XiAction {

    @Argument(index = 0, name = "source file", required = true, description = "file to be copied")
    @Completion(FileCompleter.class)
    private String source;

    @Argument(index = 1, name = "destination", required = true, description = "destination file")
    @Completion(FileCompleter.class)
    private String dest;

    @Option(name = "--force", aliases = "-f", description = "override existing file, never prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      source = expandFilepath(source);
      dest = expandFilepath(dest);

      File sourceFile = new File(source);
      if (!sourceFile.exists()) {
        throw new IllegalCmdParamException(source + " does not exist");
      }

      if (!sourceFile.isFile()) {
        throw new IllegalCmdParamException(source + " is not a file");
      }

      File destFile = new File(dest);
      if (destFile.exists()) {
        if (!destFile.isFile()) {
          throw new IllegalCmdParamException("cannot override an existing directory by a file");
        } else {
          if (!force.booleanValue() && !confirm("Do you want to override the file " + dest, 3)) {
            return null;
          }
        }
      } else {
        IoUtil.mkdirsParent(destFile.toPath());
      }

      FileUtils.copyFile(sourceFile, destFile, true);

      return null;
    }

  } // class CopyFile

  @Command(scope = "xi", name = "file-exists", description = "test whether file or folder exists")
  @Service
  public static class FileExists extends XiAction {

    @Argument(name = "target", required = true, description = "file or dir to be checked")
    @Completion(FileCompleter.class)
    private String target;

    @Override
    protected Object execute0()
            throws Exception {
      return new File(target).exists();
    }

  } // class CopyFile

  @Command(scope = "xi", name = "curl", description = "transfer a URL")
  @Service
  public static class Curl extends XiAction {

    @Argument(index = 0, name = "url", required = true, description = "URL")
    private String url;

    @Option(name = "--verbose", aliases = "-v", description = "show request and response verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--post", aliases = "-p", description = "send the request via HTTP POST")
    private Boolean usePost = Boolean.FALSE;

    @Option(name = "--data", aliases = "-d", description = "data to be sent in a POST request")
    private String postData;

    @Option(name = "--data-charset", aliases = "-c", description = "charset of data")
    private String postDataCharSet = "UTF-8";

    @Option(name = "--data-file",
        description = "file contains the data to be sent in a POST request")
    @Completion(FileCompleter.class)
    private String postDataFile;

    @Option(name = "--out", description = "where to save the response")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--header", aliases = "-h", multiValued = true,
        description = "header in request")
    private List<String> headers;

    @Option(name = "--user", aliases = "-u",
        description = "User and password of the form user:password")
    private String userPassword;

    @Reference
    private org.xipki.util.Curl curl;

    @Override
    protected Object execute0()
        throws Exception {
      byte[] content = null;
      if (postData != null) {
        content = postData.getBytes(postDataCharSet);
      } else if (postDataFile != null) {
        content = IoUtil.read(postDataFile);
      }

      if (content != null) {
        usePost = Boolean.TRUE;
      }

      Map<String, String> headerNameValues = null;
      if (headers != null) {
        headerNameValues = new HashMap<>();
        for (String header : headers) {
          int idx = header.indexOf(':');
          if (idx == -1 || idx == header.length() - 1) {
            throw new IllegalCmdParamException("invalid HTTP header: '" + header + "'");
          }

          String key = header.substring(0, idx);
          String value = header.substring(idx + 1).trim();
          headerNameValues.put(key, value);
        }
      }

      CurlResult result;
      if (usePost) {
        result = curl.curlPost(url, verbose, headerNameValues, userPassword, content);
      } else {
        result = curl.curlGet(url, verbose, headerNameValues, userPassword);
      }

      if (result.getContent() == null && result.getErrorContent() == null) {
        println("NO response content");
        return null;
      }

      if (outFile != null) {
        if (result.getContent() != null) {
          saveVerbose("saved response to file", outFile, result.getContent());
        } else {
          saveVerbose("saved (error) response to file",
              "error-" + outFile, result.getErrorContent());
        }
      } else {
        String ct = result.getContentType();
        String charset = getCharset(ct);
        if (charset == null) {
          charset = "UTF-8";
        }

        if (result.getContent() != null) {
          println(new String(result.getContent(), charset));
        } else {
          println("ERROR: ");
          println(new String(result.getContent(), charset));
        }
      }

      return null;
    } // method execute0

    private static String getCharset(String contentType) {
      if (StringUtil.isBlank(contentType) || contentType.indexOf(';') == -1) {
        return null;
      }

      StringTokenizer st = new StringTokenizer(contentType, ";");
      st.nextToken();

      while (st.hasMoreTokens()) {
        String token = st.nextToken();
        int idx = token.indexOf('=');
        if (idx == -1) {
          continue;
        }

        String paramName = token.substring(0, idx).trim();
        if ("charset".equalsIgnoreCase(paramName)) {
          return token.substring(idx + 1, token.length());
        }
      }

      return null;
    } // method getCharset

  } // class Curl

  @Command(scope = "xi", name = "mkdir", description = "make directories")
  @Service
  public static class Mkdir extends XiAction {

    @Argument(index = 0, name = "directory", required = true,
        description = "directory to be created")
    @Completion(Completers.DirCompleter.class)
    private String dirName;

    @Override
    protected Object execute0()
        throws Exception {
      File target = new File(expandFilepath(dirName));
      if (target.exists()) {
        if (!target.isDirectory()) {
          System.err.println(dirName + " exists but is not a directory, cannot override it");
          return null;
        }
      } else {
        target.mkdirs();
      }

      return null;
    }

  } // class Mkdir

  @Command(scope = "xi", name = "move-dir",
      description = "move content of the directory to destination")
  @Service
  public static class MoveDir extends XiAction {

    @Argument(index = 0, name = "source", required = true,
        description = "content of this directory will be copied")
    @Completion(Completers.DirCompleter.class)
    private String source;

    @Argument(index = 1, name = "destination", required = true,
        description = "destination directory")
    @Completion(Completers.DirCompleter.class)
    private String dest;

    @Override
    protected Object execute0()
        throws Exception {
      source = expandFilepath(source);
      dest = expandFilepath(dest);

      File sourceDir = new File(source);
      if (!sourceDir.exists()) {
        throw new IllegalCmdParamException(source + " does not exist");
      }

      if (!sourceDir.isDirectory()) {
        throw new IllegalCmdParamException(source + " is not a directory");
      }

      File destDir = new File(dest);
      if (destDir.exists()) {
        if (destDir.isFile()) {
          throw new IllegalCmdParamException(dest + " is not a directory");
        }
      } else {
        destDir.mkdirs();
      }

      FileUtils.copyDirectory(sourceDir, destDir);
      FileUtils.deleteDirectory(sourceDir);

      return null;
    }

  } // class MoveDir

  @Command(scope = "xi", name = "move-file", description = "move file")
  @Service
  public static class MoveFile extends XiAction {

    @Argument(index = 0, name = "source file", required = true, description = "file to be moved")
    @Completion(FileCompleter.class)
    private String source;

    @Argument(index = 1, name = "destination", required = true, description = "destination file")
    @Completion(FileCompleter.class)
    private String dest;

    @Option(name = "--force", aliases = "-f", description = "override existing file, never prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      source = expandFilepath(source);
      dest = expandFilepath(dest);

      File sourceFile = new File(source);
      if (!sourceFile.exists()) {
        throw new IllegalCmdParamException(source + " does not exist");
      }

      if (!sourceFile.isFile()) {
        throw new IllegalCmdParamException(source + " is not a file");
      }

      File destFile = new File(dest);
      if (destFile.exists()) {
        if (!destFile.isFile()) {
          throw new IllegalCmdParamException("cannot override an existing directory by a file");
        } else {
          if (!force.booleanValue() && !confirm("Do you want to override the file " + dest, 3)) {
            return null;
          }
        }
      } else {
        IoUtil.mkdirsParent(destFile.toPath());
      }

      FileUtils.copyFile(sourceFile, destFile, true);
      sourceFile.delete();

      return null;
    }

  } // class MoveFile

  @Command(scope = "xi", name = "replace", description = "replace text in file")
  @Service
  public static class Replace extends XiAction {

    @Argument(index = 0, name = "file", required = true, description = "file")
    @Completion(FileCompleter.class)
    private String source;

    @Option(name = "--old", required = true, description = "text to be replaced")
    private String oldText;

    @Option(name = "--new", required = true, description = "next text")
    private String newText;

    @Override
    protected Object execute0()
        throws Exception {
      File sourceFile = new File(expandFilepath(source));
      if (!sourceFile.exists()) {
        System.err.println(source + " does not exist");
        return null;
      }

      if (!sourceFile.isFile()) {
        System.err.println(source + " is not a file");
        return null;
      }

      Args.notBlank(oldText, "oldText");
      replaceFile(sourceFile, oldText, newText);

      return null;
    }

    private void replaceFile(File file, String oldText, String newText)
        throws Exception {
      BufferedReader reader = Files.newBufferedReader(file.toPath());
      ByteArrayOutputStream writer = new ByteArrayOutputStream();

      boolean changed = false;
      try {
        String line;
        while ((line = reader.readLine()) != null) {
          if (line.contains(oldText)) {
            changed = true;
            writer.write(StringUtil.toUtf8Bytes(line.replace(oldText, newText)));
          } else {
            writer.write(StringUtil.toUtf8Bytes(line));
          }
          writer.write('\n');
        }
      } finally {
        writer.close();
        reader.close();
      }

      if (changed) {
        File newFile = new File(file.getPath() + "-new");
        byte[] newBytes = writer.toByteArray();
        IoUtil.save(newFile, newBytes);
        newFile.renameTo(file);
      }
    }

  } // class Replace

  @Command(scope = "xi", name = "rm", description = "remove file or directory")
  @Service
  public static class Rm extends XiAction {

    @Argument(index = 0, name = "file", required = true,
        description = "file or directory to be deleted")
    @Completion(FileCompleter.class)
    private String targetPath;

    @Option(name = "--recursive", aliases = "-r",
        description = "remove directories and their contents recursively")
    private Boolean recursive = Boolean.FALSE;

    @Option(name = "--force", aliases = "-f", description = "remove files without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      targetPath = expandFilepath(targetPath);

      File target = new File(targetPath);
      if (!target.exists()) {
        return null;
      }

      if (target.isDirectory()) {
        if (!recursive) {
          println("Please use option --recursive to delete directory");
          return null;
        }

        if (force || confirm("Do you want to remove directory " + targetPath, 3)) {
          FileUtils.deleteDirectory(target);
          println("removed directory " + targetPath);
        }
      } else {
        if (force || confirm("Do you want to remove file " + targetPath, 3)) {
          target.delete();
          println("removed file " + targetPath);
        }
      }

      return null;
    }

  } // class Rm

  @Command(scope = "xi", name = "datetime", description = "get current date-time")
  @Service
  public static class DateTime extends XiAction {

    @Argument(name = "format", description = "format")
    @Completion(FileCompleter.class)
    private String format = "yyyyMMdd-HHmmss";

    @Override
    protected Object execute0()
            throws Exception {
      SimpleDateFormat sdf = new SimpleDateFormat(format);
      return sdf.format(new Date());
    }
  }

  @Command(scope = "xi", name = "osinfo", description = "get info of operation system")
  @Service
  public static class OsInfo extends XiAction {

    @Option(name = "--name", aliases = "-n", description = "output OS name")
    private Boolean printName;

    @Option(name = "--arch", aliases = "-a", description = "output OS arch")
    private Boolean printArch;

    @Override
    protected Object execute0()
            throws Exception {
      String name = System.getProperty("os.name").toLowerCase(Locale.ROOT);
      if (name.startsWith("windows")) {
        name = "windows";
      } else if (name.startsWith("linux")) {
        name = "linux";
      } else if (name.startsWith("mac os x")) {
        name = "macosx";
      }

      String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
      if (printName == null && printArch == null) {
        return name + "/" + arch;
      }

      boolean bName = printName == null ? false : printName.booleanValue();
      boolean bArch = printArch == null ? false : printArch.booleanValue();
      if (bName && bArch) {
        return name + "/" + arch;
      } else if (bName) {
        return name;
      } else if (bArch) {
        return arch;
      } else {
        return "";
      }
    }
  }

}
