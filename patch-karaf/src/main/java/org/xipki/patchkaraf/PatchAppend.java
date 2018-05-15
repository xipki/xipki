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

package org.xipki.patchkaraf;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.1.0
 */

public class PatchAppend {

  public PatchAppend() {
  }

  public static void main(String[] args) {
    try {
      System.exit(func(args));
    } catch (IOException ex) {
      System.err.println(ex.getMessage());
      System.exit(-1);
    }
  }

  private static int func(String[] args) throws IOException {
    if (args == null || args.length == 0 || args[0].equals("--help") || args.length % 2 != 0) {
      return printUsage("");
    }

    String fileName = null;
    String appendValue = null;
    String appendValueFileName = null;
    boolean backup = true;

    for (int i = 0; i < args.length; i += 2) {
      String option = args[i];
      String value = args[i + 1];
      if ("--file".equalsIgnoreCase(option)) {
        fileName = value;
      } else if ("--value".equalsIgnoreCase(option)) {
        appendValue = value;
      } else if ("--value-file".equalsIgnoreCase(option)) {
        appendValueFileName = value;
      } else if ("--backup".equalsIgnoreCase(option)) {
        backup = Boolean.parseBoolean(value);
      }
    }

    if (PatchUtil.isBlank(fileName)) {
      return printUsage("file is not specified");
    }

    if (PatchUtil.isBlank(appendValue) && PatchUtil.isBlank(appendValueFileName)) {
      return printUsage("nothing to patch");
    }

    File file = new File(fileName);
    File tmpNewFile = new File(fileName + ".new");
    BufferedReader reader = new BufferedReader(new FileReader(file));
    BufferedWriter writer = new BufferedWriter(new FileWriter(tmpNewFile));
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        writer.write(line);
        writer.write('\n');
      }

      if (!PatchUtil.isBlank(appendValue)) {
        writer.write(appendValue);
        writer.write('\n');
      } else {
        reader.close();
        reader = new BufferedReader(new FileReader(appendValueFileName));
        while ((line = reader.readLine()) != null) {
          writer.write(line);
          writer.write('\n');
        }
      }
    } finally {
      reader.close();
      writer.close();
    }

    if (backup) {
      File origFile = new File(fileName + ".orig");
      if (!file.renameTo(origFile)) {
        return printUsage("could not rename " + file.getPath() + " to " + origFile.getPath());
      }
    }

    if (!tmpNewFile.renameTo(file)) {
      return printUsage("could not rename " + tmpNewFile.getPath() + " to " + file.getPath());
    }

    System.out.println("Patched file " + fileName);
    return 0;
  }

  private static int printUsage(String message) {
    StringBuilder sb = new StringBuilder();
    if (!PatchUtil.isBlank(message)) {
      sb.append(message).append("\n");
    }

    sb.append("\nSYNTAX");
    sb.append("\n\tjava " + PatchAppend.class.getName() + " [options]");
    sb.append("\nOPTIONS");
    sb.append("\n\t--file");
    sb.append("\n\t\tFile to be patched");
    sb.append("\n\t--backup");
    sb.append("\n\t\tWhether to create a backup of the patched file (with appendxi .orig)");
    sb.append("\n\t\t(defaults to true)");
    sb.append("\n\t--value");
    sb.append("\n\t\tContent to be appended");
    sb.append("\n\t--value-file");
    sb.append("\n\t\tFile that contains the content to be appended");
    sb.append("\n\t--help");
    sb.append("\n\t\tDisplay this help message");

    System.out.println(sb.toString());
    return -1;
  }

}
