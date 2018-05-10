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
import org.xipki.common.util.Hex;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "delete-objects-p11",
    description = "delete objects in PKCS#11 device")
@Service
public class P11ObjectsDeleteAction extends P11SecurityAction {

  @Option(name = "--id",
      description = "id (hex) of the objects in the PKCS#11 device\n"
          + "at least one of id and label must be specified")
  private String id;

  @Option(name = "--label",
      description = "label of the objects in the PKCS#11 device\n"
          + "at least one of id and label must be specified")
  private String label;

  @Override
  protected Object execute0() throws Exception {
    P11Slot slot = getSlot();
    byte[] idBytes = null;
    if (id != null) {
      idBytes = Hex.decode(id);
    }
    int num = slot.removeObjects(idBytes, label);
    println("deleted " + num + " objects");
    return null;
  }

}
