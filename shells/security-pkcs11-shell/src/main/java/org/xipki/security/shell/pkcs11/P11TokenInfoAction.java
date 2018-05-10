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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.shell.pkcs11.completer.P11ModuleNameCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "token-info-p11",
    description = "list objects in PKCS#11 device")
@Service
public class P11TokenInfoAction extends SecurityAction {

  @Option(name = "--verbose", aliases = "-v",
      description = "show object information verbosely")
  private Boolean verbose = Boolean.FALSE;

  @Option(name = "--module",
      description = "name of the PKCS#11 module.")
  @Completion(P11ModuleNameCompleter.class)
  private String moduleName = P11SecurityAction.DEFAULT_P11MODULE_NAME;

  @Option(name = "--slot",
      description = "slot index")
  private Integer slotIndex;

  @Reference (optional = true)
  protected P11CryptServiceFactory p11CryptServiceFactory;

  @Override
  protected Object execute0() throws Exception {
    P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
    if (p11Service == null) {
      throw new IllegalCmdParamException("undefined module " + moduleName);
    }

    P11Module module = p11Service.getModule();
    println("module: " + moduleName);
    println(module.getDescription());

    List<P11SlotIdentifier> slots = module.getSlotIds();
    if (slotIndex == null) {
      output(slots);
      return null;
    }

    P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
    P11Slot slot = module.getSlot(slotId);
    println("Details of slot");
    slot.showDetails(System.out, verbose);
    System.out.println();
    System.out.flush();
    return null;
  }

  private void output(List<P11SlotIdentifier> slots) {
    // list all slots
    final int n = slots.size();

    if (n == 0 || n == 1) {
      String numText = (n == 0) ? "no" : "1";
      println(numText + " slot is configured");
    } else {
      println(n + " slots are configured");
    }

    for (P11SlotIdentifier slotId : slots) {
      println("\tslot[" + slotId.getIndex() + "]: " + slotId.getId());
    }
  }

}
