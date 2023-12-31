// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.util.CollectionUtil;

import java.util.Map;

/**
 * Actions to operate on databases directly.
 *
 * @author Lijun Liao (xipki)
 * @since  6.0.0
 */
public class DbSchemaActions {

  @Command(scope = "ca", name = "dbschema-add", description = "add DBSchema entry")
  @Service
  public static class AddDbSchema extends CaActions.CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "DBSchema entry name")
    private String name;

    @Option(name = "--value", aliases = "-v", required = true, description = "DBSchema entry value")
    private String value;

    @Override
    protected Object execute0() throws Exception {
      caManager.addDbSchema(name, value);
      return null;
    }
  } // class AddDbSchema

  @Command(scope = "ca", name = "dbschema-up", description = "change DBSchema entry")
  @Service
  public static class ChangeDbSchema extends CaActions.CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "DBSchema entry name")
    private String name;

    @Option(name = "--value", aliases = "-v", required = true, description = "DBSchema entry value")
    private String value;

    @Override
    protected Object execute0() throws Exception {
      caManager.changeDbSchema(name, value);
      return null;
    }
  } // class AddDbSchema

  @Command(scope = "ca", name = "dbschema-rm", description = "remove DBSchema entry")
  @Service
  public static class RemoveDbSchema extends CaActions.CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "DBSchema entry name")
    private String name;

    @Override
    protected Object execute0() throws Exception {
      caManager.removeDbSchema(name);
      return null;
    }
  } // class AddDbSchema

  @Command(scope = "ca", name = "dbschema-info", description = "list DBSchema entries")
  @Service
  public static class ListDbSchemas extends CaActions.CaAction {

    @Override
    protected Object execute0() throws Exception {
      Map<String, String> result = caManager.getDbSchemas();
      if (CollectionUtil.isEmpty(result)) {
        println("found no DBSchema entries");
        return null;
      }

      StringBuilder sb = new StringBuilder();
      for (Map.Entry<String, String> entry : result.entrySet()) {
        sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
      }
      print(sb.toString());

      return null;
    }
  } // class AddDbSchema

}
