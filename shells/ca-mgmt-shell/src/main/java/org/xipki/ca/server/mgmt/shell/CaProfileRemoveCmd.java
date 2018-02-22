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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameCompleter;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "caprofile-rm",
    description = "remove certificate profile from CA")
@Service
public class CaProfileRemoveCmd extends CaAction {

  @Option(name = "--ca", required = true,
      description = "CA name\n(required)")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--profile", required = true, multiValued = true,
      description = "certificate profile name\n(required, multi-valued)")
  @Completion(ProfileNameCompleter.class)
  private List<String> profileNames;

  @Override
  protected Object execute0() throws Exception {
    for (String profileName : profileNames) {
      boolean bo = caManager.removeCertprofileFromCa(profileName, caName);
      output(bo, "removed", "could not remove",
          StringUtil.concat("certificate profile ", profileName, " from CA ", caName));
    }
    return null;
  }

}
