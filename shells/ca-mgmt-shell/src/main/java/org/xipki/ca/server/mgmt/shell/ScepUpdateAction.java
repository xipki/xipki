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

package org.xipki.ca.server.mgmt.shell;

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.SignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ScepNameCompleter;
import org.xipki.common.util.CollectionUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "scep-up",
    description = "Update SCEP")
@Service
public class ScepUpdateAction extends CaAction {

  @Option(name = "--name", required = true,
      description = "name\n(required)")
  @Completion(ScepNameCompleter.class)
  private String name;

  @Option(name = "--ca",
      description = "CA name")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--active",
      description = "activate this SCEP")
  private Boolean active;

  @Option(name = "--inactive",
      description = "deactivate this SCEP")
  private Boolean inactive;

  @Option(name = "--responder",
      description = "Responder name")
  @Completion(SignerNameCompleter.class)
  private String responderName;

  @Option(name = "--profile", multiValued = true,
      description = "profile name or 'all' for all profiles\n(multi-valued)")
  @Completion(ProfileNameAndAllCompleter.class)
  private Set<String> profiles;

  @Option(name = "--control",
      description = "SCEP control or 'null'")
  private String control;

  @Override
  protected Object execute0() throws Exception {
    Boolean realActive;
    if (active != null) {
      if (inactive != null) {
        throw new IllegalCmdParamException(
            "maximal one of --active and --inactive can be set");
      }
      realActive = Boolean.TRUE;
    } else if (inactive != null) {
      realActive = Boolean.FALSE;
    } else {
      realActive = null;
    }

    ChangeScepEntry entry = new ChangeScepEntry(name);
    if (realActive != null) {
      entry.setActive(realActive);
    }

    if (caName != null) {
      entry.setCa(new NameId(null, caName));
    }

    if (responderName != null) {
      entry.setResponderName(responderName);
    }

    if (CollectionUtil.isNonEmpty(profiles)) {
      if (profiles.contains("NONE")) {
        profiles.clear();
      }
    }

    if (control != null) {
      entry.setControl(control);
    }

    String msg = "SCEP responder " + name;
    try {
      caManager.changeScep(entry);
      println("updated " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
    }
  } // method execute0

}
