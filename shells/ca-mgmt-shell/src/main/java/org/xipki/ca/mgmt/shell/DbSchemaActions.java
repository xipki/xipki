/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.util.CollectionUtil;

import java.util.Map;

/**
 * Actions to operate on databases directly.
 *
 * @author Lijun Liao
 * @since  5.4.0
 */
public class DbSchemaActions {

  @Command(scope = "ca", name = "dbschema-add", description = "add DBSchema entry")
  @Service
  public static class AddDbSchema extends CaActions.CaAction {

    @Option(name = "--name", aliases = "-n", required = true,
        description = "DBSchema entry name")
    private String name;

    @Option(name = "--value", aliases = "-v", required = true,
        description = "DBSchema entry value")
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

    @Option(name = "--name", aliases = "-n", required = true,
            description = "DBSchema entry name")
    private String name;

    @Option(name = "--value", aliases = "-v", required = true,
            description = "DBSchema entry value")
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

    @Option(name = "--name", aliases = "-n", required = true,
            description = "DBSchema entry name")
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
