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
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ResponderNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ScepNameCompleter;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.password.PasswordResolver;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "scep-add",
    description = "add SCEP")
@Service
public class ScepAddCmd extends CaAction {

  @Option(name = "--name", required = true,
      description = "name\n(required)")
  private String name;

  @Option(name = "--ca", required = true,
      description = "CA name\n(required)")
  @Completion(ScepNameCompleter.class)
  private String caName;

  @Option(name = "--inactive",
      description = "do not activate this SCEP")
  private Boolean inactive = Boolean.FALSE;

  @Option(name = "--responder", required = true,
      description = "Responder name\n(required)")
  @Completion(ResponderNameCompleter.class)
  private String responderName;

  @Option(name = "--control",
      description = "SCEP control")
  private String scepControl;

  @Option(name = "--profile", required = true, multiValued = true,
      description = "profile name or 'all' for all profiles\n(required, multi-valued)")
  @Completion(ProfileNameAndAllCompleter.class)
  private Set<String> profiles;

  @Reference
  private PasswordResolver passwordResolver;

  @Override
  protected Object execute0() throws Exception {
    ScepEntry entry = new ScepEntry(name, new NameId(null, caName), !inactive, responderName,
        profiles, scepControl);

    String msg = "SCEP " + name;
    try {
      caManager.addScep(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
