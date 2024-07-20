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
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A tool to replace text in files.
 * @author Lijun Liao (xipki)
 */

public class BatchReplace {

  private static class Section {
    private String description;
    private Set<String> files;
    private Map<String, String> replacements;

    public void setDescription(String description) {
      this.description = description;
    }

    public void setFiles(Set<String> files) {
      this.files = files;
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
        for (String filename : section.files) {
          System.out.println("    File " + filename);
          File file = new File(filename);
          if (!file.isAbsolute()) {
            file = new File(basedir, filename);
          }
          replaceFile(file, section.replacements, prefix, suffix);
        }
      }
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(1);
    }
  }

  private static void replaceFile(File file, Map<String, String> replacements, String prefix, String suffix)
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
      try (OutputStream out = new FileOutputStream(file)) {
        out.write(target.toString().getBytes(StandardCharsets.UTF_8));
      }
    }
  }

}
