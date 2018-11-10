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

package org.xipki.ca.mgmt.shell.completer;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class RcaNameCompleter extends MgmtNameCompleter {

  @Override
  protected Set<String> getEnums() {
    Set<String> caNames;
    try {
      caNames = caManager.getCaNames();
    } catch (CaMgmtException ex) {
      return Collections.emptySet();
    }

    Set<String> ret = new HashSet<>();

    for (String name : caNames) {
      CaEntry caEntry;
      try {
        caEntry = caManager.getCa(name);
      } catch (CaMgmtException ex) {
        continue;
      }

      X509Certificate cert = caEntry.getCert();
      if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
        ret.add(name);
      }
    }
    return ret;
  }

}
