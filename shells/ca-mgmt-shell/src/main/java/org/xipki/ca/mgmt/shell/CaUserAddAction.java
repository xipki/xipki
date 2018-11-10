/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.mgmt.api.CaHasUserEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "ca", name = "causer-add", description = "add user to CA")
@Service
public class CaUserAddAction extends CaAction {

  @Option(name = "--ca", required = true, description = "CA name")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--user", required = true, description = "user name")
  private String userName;

  @Option(name = "--permission", required = true, multiValued = true, description = "permission")
  @Completion(PermissionCompleter.class)
  private Set<String> permissions;

  @Option(name = "--profile", required = true, multiValued = true,
      description = "profile name or 'all' for all profiles")
  @Completion(ProfileNameAndAllCompleter.class)
  private Set<String> profiles;

  @Override
  protected Object execute0() throws Exception {
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
  }

}
