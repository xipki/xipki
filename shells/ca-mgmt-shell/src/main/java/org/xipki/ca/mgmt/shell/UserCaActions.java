/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.entry.AddUserEntry;
import org.xipki.ca.api.mgmt.entry.CaHasUserEntry;
import org.xipki.ca.api.mgmt.entry.ChangeUserEntry;
import org.xipki.ca.api.mgmt.entry.UserEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Actions to manage users.
 *
 * @author Lijun Liao
 *
 */
public class UserCaActions {

  @Command(scope = "ca", name = "causer-add", description = "add user to CA")
  @Service
  public static class CauserAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--user", required = true, description = "user name")
    private String userName;

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", required = true, multiValued = true,
        description = "profile name or 'all' for all profiles")
    @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0()
        throws Exception {
      CaHasUserEntry entry = new CaHasUserEntry(new NameId(null, userName));
      entry.setProfiles(profiles);
      int intPermission = ShellUtil.getPermission(permissions);
      entry.setPermission(intPermission);

      String msg = "user " + userName + " to CA " + caName;
      try {
        caManager.addUserToCa(entry, caName);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class CauserAdd

  @Command(scope = "ca", name = "causer-rm", description = "remove user from CA")
  @Service
  public static class CauserRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--user", required = true, description = "user name")
    private String userName;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      String msg = "user " + userName + " from CA " + caName;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeUserFromCa(userName, caName);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class CauserRm

  @Command(scope = "ca", name = "user-add", description = "add user")
  @Service
  public static class UserAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--password", description = "user password")
    private String password;

    @Option(name = "--inactive", description = "do not activate this user")
    private Boolean inactive = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      if (password == null) {
        password = new String(readPassword());
      }
      AddUserEntry userEntry =
          new AddUserEntry(new NameId(null, name), !inactive, password);
      String msg = "user " + name;
      try {
        caManager.addUser(userEntry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class UserAdd

  @Command(scope = "ca", name = "user-info", description = "show information of user")
  @Service
  public static class UserInfo extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "user name")
    private String name;

    @Override
    protected Object execute0()
        throws Exception {
      UserEntry userEntry = caManager.getUser(name);
      if (userEntry == null) {
        throw new CmdFailure("no user named '" + name + "' is configured");
      }

      StringBuilder sb = new StringBuilder();
      sb.append(userEntry);

      Map<String, CaHasUserEntry> caHasUsers = caManager.getCaHasUsersForUser(name);
      for (Entry<String, CaHasUserEntry> entry : caHasUsers.entrySet()) {
        String ca = entry.getKey();
        sb.append("\n----- CA ").append(ca).append("-----");
        sb.append("\nprofiles: ").append(entry.getValue().getProfiles());
        sb.append("\npermission: ").append(
            PermissionConstants.permissionToString(entry.getValue().getPermission()));
      }
      println(sb.toString());
      return null;
    } // method execute0

  } // class UserInfo

  @Command(scope = "ca", name = "user-rm", description = "remove user")
  @Service
  public static class UserRm extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      String msg = "user " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeUser(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class UserRm

  @Command(scope = "ca", name = "user-up", description = "update user")
  @Service
  public static class UserUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--active", description = "activate this user")
    private Boolean active;

    @Option(name = "--inactive", description = "deactivate this user")
    private Boolean inactive;

    @Option(name = "--password", description = "user password, 'CONSOLE' to read from console")
    private String password;

    @Override
    protected Object execute0()
        throws Exception {
      Boolean realActive;
      if (active != null) {
        if (inactive != null) {
          throw new IllegalCmdParamException("maximal one of --active and --inactive can be set");
        }
        realActive = Boolean.TRUE;
      } else if (inactive != null) {
        realActive = Boolean.FALSE;
      } else {
        realActive = null;
      }

      ChangeUserEntry entry = new ChangeUserEntry(new NameId(null, name));
      if (realActive != null) {
        entry.setActive(realActive);
      }

      if ("CONSOLE".equalsIgnoreCase(password)) {
        password = new String(readPassword());
      }

      if (password != null) {
        entry.setPassword(password);
      }

      String msg = "user " + name;
      try {
        caManager.changeUser(entry);
        println("changed " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not change " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class UserUp

}
