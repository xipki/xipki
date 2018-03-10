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

package org.xipki.security.shell.p11;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.Hex;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "rm-cert-p11",
    description = "remove certificate from PKCS#11 device")
@Service
public class P11CertDeleteCmd extends SecurityAction {

  @Option(name = "--slot", required = true,
      description = "slot index\n(required)")
  private Integer slotIndex;

  @Option(name = "--id", required = true,
      description = "id of the certificate in the PKCS#11 device\n(required)")
  private String id;

  @Option(name = "--module",
      description = "name of the PKCS#11 module.")
  @Completion(P11ModuleNameCompleter.class)
  private String moduleName = DEFAULT_P11MODULE_NAME;

  @Override
  protected Object execute0() throws Exception {
    P11Slot slot = getSlot(moduleName, slotIndex);
    P11ObjectIdentifier objectId = slot.getObjectIdForId(Hex.decode(id));
    slot.removeCerts(objectId);
    println("deleted certificates");
    return null;
  }

}
