// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Variable and argument context for interactive and scripted shell execution.
 *
 * @author Lijun Liao (xipki)
 */
final class ShellScriptContext implements ShellVariableSupport.Resolver {

  private final Map<String, Object> variables;

  private final List<String> args;

  private final Path workingDir;

  ShellScriptContext(List<String> args, Path workingDir) {
    this.variables = new HashMap<>();
    this.args = args == null ? List.of() : new ArrayList<>(args);
    this.workingDir = workingDir == null ? Paths.get(".") : workingDir;
  }

  private ShellScriptContext(Map<String, Object> variables, List<String> args, Path workingDir,
      boolean shareVariables) {
    this.variables = shareVariables ? variables : new HashMap<>(variables);
    this.args = args == null ? List.of() : new ArrayList<>(args);
    this.workingDir = workingDir == null ? Paths.get(".") : workingDir;
  }

  ShellScriptContext child() {
    return this;
  }

  ShellScriptContext child(List<String> newArgs) {
    return new ShellScriptContext(variables, newArgs, workingDir, true);
  }

  ShellScriptContext withWorkingDir(Path newWorkingDir) {
    return new ShellScriptContext(variables, args, newWorkingDir, true);
  }

  void set(String name, Object value) {
    variables.put(name, value);
  }

  void unset(String name) {
    variables.remove(name);
  }

  List<String> args() {
    return new ArrayList<>(args);
  }

  Path workingDir() {
    return workingDir;
  }

  @Override
  public String lookup(String bracedName, String simpleName) {
    if (bracedName != null) {
      if (bracedName.startsWith("env:")) {
        String envName = bracedName.substring(4);
        return System.getenv(envName);
      }
      if (bracedName.startsWith("sys:")) {
        String propName = bracedName.substring(4);
        return System.getProperty(propName);
      }
      Object value = variables.get(bracedName);
      return value == null ? "" : stringValue(value);
    }

    if (simpleName == null) {
      return null;
    }

    if (simpleName.matches("[0-9]+")) {
      int idx = Integer.parseInt(simpleName) - 1;
      return idx >= 0 && idx < args.size() ? args.get(idx) : "";
    }

    Object value = variables.get(simpleName);
    return value == null ? "" : stringValue(value);
  }

  boolean isTrue(String name) {
    Object value = variables.get(name);
    if (value == null) {
      return false;
    }
    return "true".equalsIgnoreCase(String.valueOf(value).trim());
  }

  private static String stringValue(Object value) {
    if (value == null) {
      return "";
    }

    return value instanceof List ? String.join(" ", toStringList(value))
        : String.valueOf(value);
  }

  private static List<String> toStringList(Object value) {
    if (value instanceof List) {
      List<?> list = (List<?>) value;
      List<String> ret = new ArrayList<>(list.size());
      for (Object obj : list) {
        ret.add(String.valueOf(obj));
      }
      return ret;
    }
    String str = String.valueOf(value).trim();
    if (str.startsWith("[") && str.endsWith("]")) {
      str = str.substring(1, str.length() - 1).trim();
    }
    if (str.isEmpty()) {
      return List.of();
    }
    return List.of(str.split("\\s+"));
  }
}
