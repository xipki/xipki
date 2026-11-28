// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.dist;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.ca.mgmt.shell.CaMgmtShellMain;
import org.xipki.shell.demo.DemoShellMain;
import org.xipki.shell.pki.client.PkiClientShellMain;
import org.xipki.shell.qa.QaShellMain;
import org.xipki.shell.security.SecurityShellMain;
import org.xipki.shell.xi.XiShellMain;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The picocli command model of all shell modules, combined as in the QA CLI (all modules):
 * the model is valid, command names are unique, and the help of every command can be
 * rendered.
 *
 * @author Lijun Liao (xipki)
 */
public class CommandModelTest {

  @Test
  public void allCommandsHaveAValidModelAndHelp() {
    CommandLine root = new CommandLine(new XipkiQaCliMain.RootCommand());
    for (Object module : List.of(new XiShellMain.RootCommand(), new DemoShellMain.RootCommand(),
        new SecurityShellMain.RootCommand(), new PkiClientShellMain.RootCommand(),
        new CaMgmtShellMain.RootCommand(), new QaShellMain.RootCommand())) {
      // as XipkiQaCliMain.addModuleSubcommands: a duplicate name throws an exception
      for (Map.Entry<String, CommandLine> sub : new CommandLine(module).getSubcommands()
          .entrySet()) {
        root.addSubcommand(sub.getValue().getCommandName(), sub.getValue());
      }
    }

    List<String> errors = new ArrayList<>();
    int[] count = {0};
    visit(root, errors, count);
    Assert.assertTrue("commands: " + count[0], count[0] > 100);
    Assert.assertTrue(String.join("\n", errors), errors.isEmpty());
  }

  private static void visit(CommandLine cmd, List<String> errors, int[] count) {
    count[0]++;
    String name = cmd.getCommandSpec().qualifiedName();
    try {
      String usage = cmd.getUsageMessage(CommandLine.Help.Ansi.OFF);
      if (usage.isBlank()) {
        errors.add(name + ": empty help");
      }
    } catch (RuntimeException ex) {
      errors.add(name + ": " + ex);
    }

    String[] description = cmd.getCommandSpec().usageMessage().description();
    if (cmd.getParent() != null && (description == null || description.length == 0)) {
      errors.add(name + ": no description");
    }

    for (CommandLine sub : cmd.getSubcommands().values()) {
      // aliases are listed with the same CommandLine
      if (sub.getParent() == cmd && sub.getCommandName().equals(
          cmd.getSubcommands().entrySet().stream().filter(e -> e.getValue() == sub)
              .findFirst().map(Map.Entry::getKey).orElse(null))) {
        visit(sub, errors, count);
      }
    }
  }

}
