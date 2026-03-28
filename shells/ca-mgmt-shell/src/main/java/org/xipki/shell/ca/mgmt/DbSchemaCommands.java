// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.util.extra.misc.CollectionUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Actions to operate on databases directly.
 *
 * @author Lijun Liao (xipki)
 */
public class DbSchemaCommands {
  @Command(name = "dbschema-add", description = "add DBSchema entry",
      mixinStandardHelpOptions = true)
  static class AddDbSchema extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "DBSchema entry name")
    private String name;

    @Option(names = {"--value", "-v"}, required = true, description = "DBSchema entry value")
    private String value;

    @Override
    public void run() {
      try {
        client().addDbSchema(name, value);
        println("added DBSchema entry " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add DBSchema entry: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "dbschema-up", description = "change DBSchema entry",
      mixinStandardHelpOptions = true)
  static class ChangeDbSchema extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "DBSchema entry name")
    private String name;

    @Option(names = {"--value", "-v"}, required = true, description = "DBSchema entry value")
    private String value;

    @Override
    public void run() {
      try {
        client().changeDbSchema(name, value);
        println("updated DBSchema entry " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update DBSchema entry: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "dbschema-rm", description = "remove DBSchema entry",
      mixinStandardHelpOptions = true)
  static class RemoveDbSchema extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "DBSchema entry name")
    private String name;

    @Override
    public void run() {
      try {
        client().removeDbSchema(name);
        println("removed DBSchema entry " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not remove DBSchema entry: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "dbschema-info", description = "list DBSchema entries",
      mixinStandardHelpOptions = true)
  static class ListDbSchemas extends CaMgmtUtil.CaMgmtCommand {

    @Override
    public void run() {
      try {
        Map<String, String> result = client().getDbSchemas();
        if (CollectionUtil.isEmpty(result)) {
          println("found no DBSchema entries");
          return;
        }

        List<String> names = new ArrayList<>(result.keySet());
        Collections.sort(names);
        StringBuilder sb = new StringBuilder();
        for (String name : names) {
          sb.append(name).append(": ").append(result.get(name)).append('\n');
        }
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not list DBSchema entries: " + ex.getMessage(), ex);
      }
    }
  }
}
