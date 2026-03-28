// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import picocli.CommandLine;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Model.OptionSpec;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Renders shell usage and help output with shell-specific formatting and command ordering.
 *
 * @author Lijun Liao (xipki)
 */
class ShellHelpSupport {

  private final PicocliShell shell;

  ShellHelpSupport(PicocliShell shell) {
    this.shell = shell;
  }

  CommandSpec resolveCommandSpec(String[] args) {
    CommandSpec spec = shell.commandLine().getCommandSpec();
    for (String arg : args) {
      if (arg.startsWith("-")) {
        break;
      }
      CommandLine sub = spec.subcommands().get(arg);
      if (sub == null) {
        break;
      }
      spec = sub.getCommandSpec();
    }
    return spec;
  }

  void printDetachedUsage(CommandSpec spec) {
    if (spec == shell.commandLine().getCommandSpec()) {
      spec.commandLine().usage(shell.out());
      shell.out().flush();
      return;
    }

    CommandLine detached = new CommandLine(spec.userObject());
    stripVersionOptions(detached.getCommandSpec());
    flattenQualifiedNames(detached.getCommandSpec());
    enableDefaultValueDisplay(detached.getCommandSpec());
    detached.usage(shell.out());
    shell.out().flush();
  }

  void enableDefaultValueDisplay(CommandSpec spec) {
    spec.usageMessage().showDefaultValues(true);
    spec.usageMessage().sectionMap().put(
        CommandLine.Model.UsageMessageSpec.SECTION_KEY_COMMAND_LIST,
        help -> renderSortedCommandList(spec));
    for (CommandLine sub : spec.subcommands().values()) {
      enableDefaultValueDisplay(sub.getCommandSpec());
    }
  }

  void stripVersionOptions(CommandSpec spec) {
    List<OptionSpec> toRemove = new ArrayList<>();
    for (OptionSpec option : spec.options()) {
      for (String name : option.names()) {
        if ("-V".equals(name) || "--version".equals(name)) {
          toRemove.add(option);
          break;
        }
      }
    }

    for (OptionSpec option : toRemove) {
      spec.remove(option);
    }

    for (CommandLine sub : spec.subcommands().values()) {
      stripVersionOptions(sub.getCommandSpec());
    }
  }

  void flattenQualifiedNames(CommandSpec spec) {
    spec.qualifiedName(spec.name());
    for (CommandLine sub : spec.subcommands().values()) {
      flattenQualifiedNames(sub.getCommandSpec());
    }
  }

  private static String renderSortedCommandList(CommandSpec spec) {
    Map<String, CommandLine> subcommands = spec.subcommands();
    if (subcommands.isEmpty()) {
      return "";
    }

    StringBuilder sb = new StringBuilder();
    List<Map.Entry<String, CommandLine>> builtinEntries = new ArrayList<>();
    List<Map.Entry<String, CommandLine>> otherEntries = new ArrayList<>();
    for (Map.Entry<String, CommandLine> entry : subcommands.entrySet()) {
      CommandLine sub = entry.getValue();
      Object userObject = sub.getCommandSpec().userObject();
      if (isCoreShellCommand(userObject)) {
        builtinEntries.add(entry);
      } else {
        otherEntries.add(entry);
      }
    }

    builtinEntries.sort((a, b) -> a.getKey().compareTo(b.getKey()));
    otherEntries.sort((a, b) -> a.getKey().compareTo(b.getKey()));

    List<Map.Entry<String, CommandLine>> entries = new ArrayList<>(builtinEntries.size()
        + otherEntries.size());
    entries.addAll(builtinEntries);
    entries.addAll(otherEntries);

    int commandWidth = 0;
    for (Map.Entry<String, CommandLine> entry : entries) {
      commandWidth = Math.max(commandWidth, entry.getKey().length());
    }

    String indent = "  ";
    String separator = "  ";
    int descriptionWidth = Math.max(20, 80 - indent.length() - separator.length() - commandWidth);

    for (Map.Entry<String, CommandLine> entry : entries) {
      String name = entry.getKey();
      String description = firstDescriptionLine(entry.getValue().getCommandSpec());
      appendWrappedCommand(sb, indent, separator, name, commandWidth, description,
          descriptionWidth);
      if (!builtinEntries.isEmpty() && entry == builtinEntries.get(builtinEntries.size() - 1)
          && !otherEntries.isEmpty()) {
        sb.append('\n');
      }
    }

    return sb.toString();
  }

  private static boolean isCoreShellCommand(Object userObject) {
    if (userObject == null) {
      return false;
    }

    Class<?> commandClass = userObject.getClass();
    String className = commandClass.getName();
    return className.startsWith("org.xipki.shell.PicocliShell$")
        || commandClass == SourceCommand.class
        || commandClass == LessCommand.class;
  }

  private static String firstDescriptionLine(CommandSpec spec) {
    String[] description = spec.usageMessage().description();
    if (description == null || description.length == 0) {
      return "";
    }
    return description[0] == null ? "" : description[0].trim();
  }

  private static void appendWrappedCommand(StringBuilder sb, String indent, String separator,
      String name, int commandWidth, String description, int descriptionWidth) {
    String paddedName = String.format("%-" + commandWidth + "s", name);
    if (description == null || description.isEmpty()) {
      sb.append(indent).append(paddedName).append('\n');
      return;
    }

    List<String> lines = wrapDescription(description, descriptionWidth);
    sb.append(indent).append(paddedName).append(separator).append(lines.get(0)).append('\n');

    String continuationIndent = indent + " ".repeat(commandWidth) + separator;
    for (int i = 1; i < lines.size(); i++) {
      sb.append(continuationIndent).append(lines.get(i)).append('\n');
    }
  }

  private static List<String> wrapDescription(String description, int width) {
    List<String> lines = new ArrayList<>();
    String remaining = description == null ? "" : description.trim();
    while (!remaining.isEmpty()) {
      if (remaining.length() <= width) {
        lines.add(remaining);
        break;
      }

      int split = remaining.lastIndexOf(' ', width);
      if (split <= 0) {
        split = width;
      }
      lines.add(remaining.substring(0, split).trim());
      remaining = remaining.substring(split).trim();
    }

    if (lines.isEmpty()) {
      lines.add("");
    }
    return lines;
  }

}
