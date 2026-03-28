// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Shell Util.
 *
 * @author Lijun Liao (xipki)
 */
public class ShellUtil {

  private static final String SHELL_HOME = "org.xipki.shell.home";

  /**
   * Resolves a required path under the configured shell home.
   *
   * @param relativePath path relative to shell home
   * @return normalized absolute path string
   * @throws IllegalStateException if the path escapes shell home or does not exist as a file
   */
  public static String resolveRequired(String relativePath) {
    Path baseDir = shellHome();
    Path path = baseDir.resolve(relativePath).normalize();
    if (!path.startsWith(baseDir)) {
      throw new IllegalStateException("config path escapes shell home: " + relativePath);
    }
    if (!path.toFile().isFile()) {
      throw new IllegalStateException("required config file not found: " + path);
    }
    return path.toString();
  }

  /**
   * Resolves an optional path under the configured shell home.
   *
   * @param relativePath path relative to shell home
   * @return normalized absolute path string
   * @throws IOException if the path escapes shell home
   */
  public static String resolveOptional(String relativePath) throws IOException {
    Path baseDir = shellHome();
    Path path = baseDir.resolve(relativePath).normalize();
    if (!path.startsWith(baseDir)) {
      throw new IOException("config path escapes shell home: " + relativePath);
    }
    return path.toString();
  }

  /**
   * Returns the shell home directory used for bundled configuration and scripts.
   *
   * @return normalized absolute shell home path
   */
  public static Path shellHome() {
    String shellHome = System.getProperty(SHELL_HOME);
    if (shellHome == null || shellHome.isBlank()) {
      return Paths.get("").toAbsolutePath().normalize();
    }
    return Paths.get(shellHome).toAbsolutePath().normalize();
  }

  private ShellUtil() {
  }

}
