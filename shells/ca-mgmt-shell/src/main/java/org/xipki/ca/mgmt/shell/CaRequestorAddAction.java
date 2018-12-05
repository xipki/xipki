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
import org.xipki.ca.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "careq-add", description = "add requestor to CA")
@Service
public class CaRequestorAddAction extends CaAction {

  @Option(name = "--ca", required = true, description = "CA name")
  @Completion(CaCompleters.CaNameCompleter.class)
  private String caName;

  @Option(name = "--requestor", required = true, description = "requestor name")
  @Completion(CaCompleters.RequestorNameCompleter.class)
  private String requestorName;

  @Option(name = "--ra", description = "whether as RA")
  @Completion(Completers.YesNoCompleter.class)
  private String raS = "no";

  @Option(name = "--permission", required = true, multiValued = true, description = "permission")
  @Completion(CaCompleters.PermissionCompleter.class)
  private Set<String> permissions;

  @Option(name = "--profile", multiValued = true,
      description = "profile name or 'all' for all profiles")
  @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
  private Set<String> profiles;

  @Override
  protected Object execute0() throws Exception {
    boolean ra = isEnabled(raS, false, "ra");

    CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(null, requestorName));
    entry.setRa(ra);
    entry.setProfiles(profiles);
    int intPermission = ShellUtil.getPermission(permissions);
    entry.setPermission(intPermission);

    String msg = "requestor " + requestorName + " to CA " + caName;
    try {
      caManager.addRequestorToCa(entry, caName);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
