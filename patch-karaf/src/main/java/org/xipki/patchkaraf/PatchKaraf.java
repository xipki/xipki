// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.patchkaraf;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class PatchKaraf {

  private final File karafDir;

  private final String karafVersion;

  private String featuresRepos;

  private String features;

  private String exportJrePackages;

  private boolean backup = true;

  private boolean disableJmxremote = true;

  private String noStartupBundles;

  private PatchKaraf(File karafDir) throws IOException {
    this.karafDir = karafDir;

    String version = null;
    try (BufferedReader reader = new BufferedReader(new FileReader(
        new File(karafDir, "etc/distribution.info")))) {
      String line;
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (line.startsWith("karafVersion")) {
          StringTokenizer tokenizer = new StringTokenizer(line, " =");
          tokenizer.nextToken();
          version = tokenizer.nextToken();
          break;
        }
      }
    } catch (RuntimeException e) {
      throw new IOException("could not detect karaf version", e);
    }

    if (version == null) {
      throw new IOException("could not detect karaf version");
    }
    this.karafVersion = version;
  }

  public static void main(String[] args) {
    try {
      if (args == null || args.length == 0 || args[0].equals("--help")) {
        printUsage("");
        return;
      }

      String dirName = null;
      String repos = null;
      String features = null;
      String exportJrePackages = null;
      String noStartupBundles = null;
      boolean noBackup = false;
      boolean disableJmxremote = false;

      for (int i = 0; i < args.length;) {
        String option = args[i++];
        if ("--dir".equalsIgnoreCase(option)) {
          dirName = args[i++];
        } else if ("--no-backup".equalsIgnoreCase(option)) {
          noBackup = true;
        } else if ("--disable-jmxremote".equalsIgnoreCase(option)) {
          disableJmxremote = true;
        } else if ("--repos".equalsIgnoreCase(option)) {
          repos = args[i++];
        } else if ("--features".equalsIgnoreCase(option)) {
          features = args[i++];
        } else if ("--export-jre-packages".equalsIgnoreCase(option)) {
          exportJrePackages = args[i++];
        } else if ("--no-startup".equalsIgnoreCase(option)) {
          noStartupBundles = args[i++];
        } else {
          throw new IOException("unknown option '" + option + "'");
        }
      }

      if (isBlank(dirName)) {
        System.exit(printUsage("dir is not specified"));
      }

      PatchKaraf patchKaraf = new PatchKaraf(new File(dirName));
      patchKaraf.featuresRepos = repos;
      patchKaraf.features = features;
      patchKaraf.exportJrePackages = exportJrePackages;
      patchKaraf.backup = !noBackup;
      patchKaraf.disableJmxremote = disableJmxremote;
      patchKaraf.noStartupBundles = noStartupBundles;

      patchKaraf.patch();
    } catch (IOException ex) {
      ex.printStackTrace();
      System.exit(-1);
    }
  }

  private static int printUsage(String message) {
    StringBuilder sb = new StringBuilder();
    if (!isBlank(message)) {
      sb.append(message).append("\n");
    }

    sb.append("\nSYNTAX")
      .append("\n\tjava ").append(PatchKaraf.class.getName()).append(" [options]")
      .append("\nOPTIONS")
      .append("\n\t--help").append("\n\t\tDisplay this help message")
      .append("\n\t--dir").append("\n\t\tKaraf dir")
      .append("\n\t--no-backup").append("\n\t\tDo not create a backup of the patched file " +
            "(with appendix .orig)")
        .append("\n\t\t(defaults to false)")
      .append("\n\t--repos")
        .append("\n\t\tRepositories to replace in etc/org.apache.karaf.features.cfg")
      .append("\n\t--features")
        .append("\n\t\tRepositories to replace in etc/org.apache.karaf.features.cfg")
      .append("\n\t--disable-jmxremote")
        .append("\n\t\tDisable jmxremote in bin/inc")
      .append("\n\t--export-jre-packages")
        .append("\n\t\tPackages to be exported in etc/jre.properties")
      .append("\n\t--no-startup")
      .append("\n\t\tBundles to be removed from etc/startup.properties");

    System.out.println(sb);
    return -1;
  }

  private void patch() throws IOException {
    patchPaxUrlMvn();
    patchPaxLogging();
    replace("etc/startup.properties", "pax-logging-log4j2", "pax-logging-logback", false);
    patchStartup();
    patchFeatures();
    if (disableJmxremote) {
      replace("bin/inc", "-Dcom.sun.management.jmxremote", "", backup);
    }

    if (!isBlank(exportJrePackages)) {
      replace("etc/jre.properties",
          "java.applet,", "java.applet," + exportJrePackages + ",", backup);
    }

    replace("etc/system.properties",
        "karaf.clean.cache = false", "karaf.clean.cache = true", false);

    replace("etc/system.properties",
        "karaf.clean.cache=false", "karaf.clean.cache=true", backup);

    replace("etc/config.properties",
        "karaf.delay.console = false", "karaf.delay.console = true", false);

    replace("etc/config.properties",
        "karaf.delay.console=false", "karaf.delay.console=true", backup);

    append("etc/custom.properties", "karaf.shutdown.port=-1");
  }

  private void patchPaxUrlMvn() throws IOException {
    String fileName = "etc/org.ops4j.pax.url.mvn.cfg";
    System.out.println("Patching " + fileName);

    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("#org.ops4j.pax.url.mvn.localRepository")) {
          writer.write("org.ops4j.pax.url.mvn.localRepository=${karaf.home}/not-exists");
        } else if (line.startsWith("org.ops4j.pax.url.mvn.repositories=")) {
          writer.write(commentContinuedLine(reader, line));
          writer.write("\norg.ops4j.pax.url.mvn.repositories=" +
              "http://127.0.0.1/notexists@id=dummy");
        } else {
          writer.write(line);
        }

        writer.write('\n');
      }
    }

    rename(file, newFile, backup);
  }

  private void patchPaxLogging() throws IOException {
    String fileName = "etc/org.ops4j.pax.logging.cfg";
    System.out.println("Patching " + fileName);

    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      writer.write("org.ops4j.pax.logging.logback.config.file=${karaf.etc}/logback.xml\n");
      String line;
      while ((line = reader.readLine()) != null) {
        writer.write(line);
        writer.write('\n');
      }
    }

    rename(file, newFile, backup);
  }

  private void patchStartup() throws IOException {
    if (isBlank(noStartupBundles)) {
      return;
    }

    String fileName = "etc/startup.properties";
    System.out.println("Patching " + fileName);

    List<String> bundles = new LinkedList<>();
    StringTokenizer tokenizer = new StringTokenizer(noStartupBundles, ", ");
    while (tokenizer.hasMoreTokens()) {
      bundles.add(tokenizer.nextToken());
    }

    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        boolean contains = false;
        for (String bundle : bundles) {
          if (line.contains(bundle)) {
            contains = true;
            break;
          }
        }

        if (contains) {
          writer.write("# ");
        }
        writer.write(line);
        writer.write('\n');
      }
    }

    rename(file, newFile, backup);
  }

  private void patchFeatures() throws IOException {
    if (isBlank(featuresRepos) && isBlank(features)) {
      return;
    }

    String fileName = "etc/org.apache.karaf.features.cfg";
    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("featuresRepositories =") && !isBlank(featuresRepos)) {
          readContinuedLine(reader, line);
          writer.write("featuresRepositories = " + featuresRepos + "\n");
        } else if (line.startsWith("featuresBoot =") && !isBlank(features)) {
          readContinuedLine(reader, line);
          writer.write("featuresBoot = " + features + "\n");
        } else {
          writer.write(line);
        }

        writer.write('\n');
      }
    }

    rename(file, newFile, backup);
  }

  private void replace(String fileName, String src, String target, boolean backup)
      throws IOException {
    System.out.println("Patching " + fileName);

    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.contains(src)) {
          String newLine = line.replace(src, target);
          writer.write(newLine);
        } else {
          writer.write(line);
        }

        writer.write('\n');
      }
    }

    rename(file, newFile, backup);
  }

  private void append(String fileName, String text) throws IOException {
    System.out.println("Patching " + fileName);

    File file    = new File(karafDir, fileName);
    File newFile = new File(file.getPath() + ".new");
    try (BufferedReader reader = new BufferedReader(new FileReader(file));
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        writer.write(line);
        writer.write('\n');
      }

      writer.write('\n');
      writer.write(text);
    }

    rename(file, newFile, backup);
  }

  private static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  private static String readContinuedLine(BufferedReader reader, String startLine)
      throws IOException {
    if (!startLine.endsWith("\\")) {
      return startLine;
    }

    StringBuilder buf = new StringBuilder();
    buf.append(startLine, 0, startLine.length() - 1);

    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.endsWith("\\")) {
        buf.append(line);
        break;
      }

      buf.append(line, 0, line.length() - 1);
    }

    return buf.toString();
  }

  private static String commentContinuedLine(BufferedReader reader, String startLine)
      throws IOException {
    if (!startLine.endsWith("\\")) {
      return "#" + startLine;
    }

    StringBuilder buf = new StringBuilder();
    buf.append("#").append(startLine).append("\n");

    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.endsWith("\\")) {
        buf.append("#").append(line);
        break;
      }

      buf.append("#").append(line).append("\n");
    }

    return buf.toString();
  }

  private void rename(File file, File newFile, boolean backup) throws IOException {
    if (backup) {
      File origFile = new File(file.getPath() + ".orig");
      if (!doRename(file, origFile)) {
        throw new IOException("could not rename " + file.getPath() + " to " + origFile.getPath());
      }
    }

    if (!doRename(newFile, file)) {
      throw new IOException("could not rename " + newFile.getPath() + " to " + file.getPath());
    }

    System.out.println("Patched file " + file.getPath());
  }

  private static boolean doRename(File from, File to) {
    if (to.exists()) {
      to.delete();
    }

    return from.renameTo(to);
  }

}
