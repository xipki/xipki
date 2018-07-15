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

package org.xipki.security.shell.pkcs11;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.util.Hex;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "delete-cert-p11",
    description = "remove certificate from PKCS#11 device")
@Service
public class P11CertDeleteAction extends P11SecurityAction {

  @Option(name = "--id", required = true,
      description = "id of the certificate in the PKCS#11 device")
  private String id;

  @Option(name = "--force", aliases = "-f", description = "without prompt")
  private Boolean force = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    if (force || confirm("Do you want to remove PKCS#11 certificate object with id " + id, 3)) {
      P11Slot slot = getSlot();
      P11ObjectIdentifier objectId = slot.getObjectId(Hex.decode(id), null);
      slot.removeCerts(objectId);
      println("deleted certificates");
    }
    return null;
  }

}
