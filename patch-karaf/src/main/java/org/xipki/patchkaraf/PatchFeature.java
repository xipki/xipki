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
import java.util.StringTokenizer;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.1.0
 */

public class PatchFeature {

  public PatchFeature() {
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
    String repos = null;
    String features = null;
    boolean backup = true;

    for (int i = 0; i < args.length; i += 2) {
      String option = args[i];
      String value = args[i + 1];
      if ("--file".equalsIgnoreCase(option)) {
        fileName = value;
      } else if ("--repos".equalsIgnoreCase(option)) {
        repos = value;
      } else if ("--features".equalsIgnoreCase(option)) {
        features = value;
      } else if ("--backup".equalsIgnoreCase(option)) {
        backup = Boolean.parseBoolean(value);
      }
    }

    if (PatchUtil.isBlank(fileName)) {
      return printUsage("file is not specified");
    }

    if (PatchUtil.isBlank(repos) && PatchUtil.isBlank(features)) {
      return printUsage("nothing to patch");
    }

    File file = new File(fileName);
    File tmpNewFile = new File(fileName + ".new");
    BufferedReader reader = new BufferedReader(new FileReader(file));
    BufferedWriter writer = new BufferedWriter(new FileWriter(tmpNewFile));
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("featuresRepositories =") && !PatchUtil.isBlank(repos)) {
          String line2 = PatchUtil.readContinuedLine(reader, line);
          StringBuilder sb = new StringBuilder();
          sb.append("featuresRepositories = \\\n");
          StringTokenizer reposTokenizer = new StringTokenizer(repos, ", \n\r");
          while (reposTokenizer.hasMoreTokens()) {
            sb.append("    ").append(reposTokenizer.nextToken()).append(", \\\n");
          }

          String value2 = line2.substring("featuresRepositories =".length()).trim();
          reposTokenizer = new StringTokenizer(value2, ", \n\r");
          while (reposTokenizer.hasMoreTokens()) {
            sb.append("    ").append(reposTokenizer.nextToken()).append(", \\\n");
          }
          int len = sb.length();
          sb.delete(len - 4, len);
          writer.write(sb.toString());
        } else if (line.startsWith("featuresBoot =") && !PatchUtil.isBlank(features)) {
          String line2 = PatchUtil.readContinuedLine(reader, line);
          StringBuilder sb = new StringBuilder();
          sb.append("featuresBoot = \\\n");

          boolean addPhase = features.startsWith("(");
          if (addPhase) {
            sb.append("    ( \\\n");
          }

          String value2 = line2.substring("featuresBoot =".length()).trim();
          StringTokenizer featuresTokenizer = new StringTokenizer(value2, ", \n\r");
          while (featuresTokenizer.hasMoreTokens()) {
            sb.append("    ").append(featuresTokenizer.nextToken()).append(", \\\n");
          }

          if (addPhase) {
            int index = features.indexOf(')');
            String phase0Features = features.substring(1, index).trim();
            if (!phase0Features.isEmpty()) {
              // no additional phase 0 feature
              features = features.substring(index + 1);
              featuresTokenizer = new StringTokenizer(phase0Features, ", \n\r");
              while (featuresTokenizer.hasMoreElements()) {
                sb.append("    ").append(featuresTokenizer.nextToken()).append(", \\\n");
              }
            }
          }

          int len = sb.length();
          sb.delete(len - 4, len);
          if (addPhase) {
            sb.append(")");
          }
          sb.append(", \\\n");

          featuresTokenizer = new StringTokenizer(features, ", \n\r");
          while (featuresTokenizer.hasMoreTokens()) {
            sb.append("    ").append(featuresTokenizer.nextToken()).append(", \\\n");
          }
          len = sb.length();
          sb.delete(len - 4, len);
          writer.write(sb.toString());
        } else {
          writer.write(line);
        }

        writer.write('\n');
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
    sb.append("\n\tjava " + PatchFeature.class.getName() + " [options]");
    sb.append("\nOPTIONS");
    sb.append("\n\t--file");
    sb.append("\n\t\tFile to be patched");
    sb.append("\n\t--backup");
    sb.append("\n\t\tWhether to create a backup of the patched file (with appendxi .orig)");
    sb.append("\n\t\t(defaults to true)");
    sb.append("\n\t--repos");
    sb.append("\n\t\tComma-separated repositories");
    sb.append("\n\t--features");
    sb.append("\n\t\tFeatures in form of [(f1,...,fk),]fk+1,fn where fx is the feature name");
    sb.append("\n\t--help");
    sb.append("\n\t\tDisplay this help message");

    System.out.println(sb.toString());
    return -1;
  }

}
