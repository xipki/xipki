// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A tool to replace text in files.
 * @author Lijun Liao (xipki)
 */

public class BatchReplace {

  public static class Includes {
    private Set<String> suffixes;
    private Set<String> dirs;

    public Set<String> getSuffixes() {
      return suffixes;
    }

    public void setSuffixes(Set<String> suffixes) {
      this.suffixes = suffixes;
    }

    public Set<String> getDirs() {
      return dirs;
    }

    public void setDirs(Set<String> dirs) {
      this.dirs = dirs;
    }
  }

  public static class Excludes {
    private Set<String> dirs;
    private Set<String> files;

    public Set<String> getDirs() {
      return dirs;
    }

    public void setDirs(Set<String> dirs) {
      this.dirs = dirs;
    }

    public Set<String> getFiles() {
      return files;
    }

    public void setFiles(Set<String> files) {
      this.files = files;
    }
  }

  private static class Section {
    private String description;
    private Includes includes;
    private Excludes excludes;
    private Map<String, String> replacements;

    public void setDescription(String description) {
      this.description = description;
    }

    public String getDescription() {
      return description;
    }

    public Includes getIncludes() {
      return includes;
    }

    public void setIncludes(Includes includes) {
      this.includes = includes;
    }

    public Excludes getExcludes() {
      return excludes;
    }

    public void setExcludes(Excludes excludes) {
      this.excludes = excludes;
    }

    public Map<String, String> getReplacements() {
      return replacements;
    }

    public void setReplacements(Map<String, String> replacements) {
      this.replacements = replacements;
    }
  }

  private static class Conf {
    private String prefix;
    private String suffix;
    private String basedir;
    private List<Section> sections;

    public void setPrefix(String prefix) {
      this.prefix = prefix;
    }

    public void setSuffix(String suffix) {
      this.suffix = suffix;
    }

    public void setBasedir(String basedir) {
      this.basedir = basedir;
    }

    public void setSections(List<Section> sections) {
      this.sections = sections;
    }
  }

  public static void main(String[] args) {
    try {
      File confFile = new File(args[0]);
      Conf conf = JSON.parseConf(confFile, Conf.class);
      String prefix = conf.prefix == null ? "" : conf.prefix;
      String suffix = conf.suffix == null ? "" : conf.suffix;

      File basedir;
      if (conf.basedir == null) {
        basedir = confFile.getParentFile();
      } else {
        basedir = new File(conf.basedir);
        if (!basedir.isAbsolute()) {
          File confFileDir = confFile.getParentFile();
          if (confFileDir != null) {
            basedir = new File(confFileDir, basedir.toString());
          }
        }
      }

      for (Section section : conf.sections) {
        System.out.println("Processing section '" + section.description + "'");

        if (section.includes == null) {
          continue;
        }

        Set<String> includeSuffixes = section.includes.suffixes;
        if (includeSuffixes == null || includeSuffixes.isEmpty()) {
          continue;
        }

        Set<String> includeDirs = section.includes.dirs;
        if (includeDirs == null || includeDirs.isEmpty()) {
          continue;
        } else {
          includeDirs = toCanonicalPaths(basedir, includeDirs);
        }

        Set<String> excludeDirs = section.excludes == null ? null : section.excludes.dirs;
        if (excludeDirs == null) {
          excludeDirs = Collections.emptySet();
        } else {
          excludeDirs = toCanonicalPaths(basedir, excludeDirs);
        }

        Set<String> excludesFiles = section.excludes == null ? null : section.excludes.files;
        if (excludesFiles == null) {
          excludesFiles = Collections.emptySet();
        } else {
          excludesFiles = toCanonicalPaths(basedir, excludesFiles);
        }

        String basedirPath = basedir.getCanonicalPath();
        if (!basedirPath.endsWith(File.separator)) {
          basedirPath += File.separator;
        }

        for (String dirName : includeDirs) {
          File dir = new File(dirName);
          replaceDir(basedirPath, dir, includeSuffixes, excludeDirs, excludesFiles,
              section.replacements, prefix, suffix);
        }
      }
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(1);
    }
  }

  private static Set<String> toCanonicalPaths(File base, Set<String> subPaths) throws IOException {
    String basePath = base.getPath();
    if (!basePath.endsWith("/")) {
      basePath += "/";
    }

    Set<String> ret = new HashSet<>(subPaths.size());
    for (String m : subPaths) {
      ret.add(new File(basePath + m).getCanonicalPath());
    }
    return ret;
  }

  private static void replaceDir(
      String baseDirPath, File dir, Set<String> includeSuffixes,
      Set<String> excludeDirs, Set<String> excludeFiles,
      Map<String, String> replacements, String prefix, String suffix)
      throws IOException {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File f : files) {
      if (f.isFile()) {
        String path = f.getPath();
        if (endsWith(path, includeSuffixes) && !excludeFiles.contains(path)) {
          replaceFile(baseDirPath, f, replacements, prefix, suffix);
        }
      } else if (f.isDirectory()) {
        if (!excludeDirs.contains(f.getPath())) {
          replaceDir(baseDirPath, f, includeSuffixes, excludeDirs, excludeFiles,
              replacements, prefix, suffix);
        }
      }
    }
  }

  private static boolean endsWith(String path, Set<String> suffixes) {
    for (String suffix : suffixes) {
      if (path.endsWith(suffix)) {
        return true;
      }
    }
    return false;
  }

  private static void replaceFile(
      String baseDirPath, File file, Map<String, String> replacements,
      String prefix, String suffix)
      throws IOException {
    StringBuilder target = new StringBuilder();
    boolean changed = false;

    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
      String line;
      while ((line = reader.readLine()) != null) {
        String origLine = line;
        for (Map.Entry<String, String> m : replacements.entrySet()) {
          String pattern = prefix + m.getKey() + suffix;
          if (line.contains(pattern)) {
            line = line.replace(pattern, m.getValue());
          }
        }

        if (!origLine.equals(line)) {
          changed = true;
        }

        target.append(line).append('\n');
      }
    }

    if (changed) {
      System.out.println("    Changed the file " + file.getPath().substring(baseDirPath.length()));
      try (OutputStream out = new FileOutputStream(file)) {
        out.write(target.toString().getBytes(StandardCharsets.UTF_8));
      }
    }
  }

}
