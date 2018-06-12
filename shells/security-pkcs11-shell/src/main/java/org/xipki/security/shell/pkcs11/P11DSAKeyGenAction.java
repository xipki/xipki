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
import org.xipki.shell.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "dsa-p11", description = "generate DSA keypair in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11DSAKeyGenAction extends P11KeyGenAction {

  @Option(name = "--plen", description = "bit length of the prime")
  private Integer plen = 2048;

  @Option(name = "--qlen", description = "bit length of the sub-prime")
  private Integer qlen;

  @Override
  protected Object execute0() throws Exception {
    if (plen % 1024 != 0) {
      throw new IllegalCmdParamException("plen is not multiple of 1024: " + plen);
    }

    if (qlen == null) {
      if (plen <= 1024) {
        qlen = 160;
      } else if (plen <= 2048) {
        qlen = 224;
      } else {
        qlen = 256;
      }
    }

    P11Slot slot = getSlot();
    P11ObjectIdentifier objId = slot.generateDSAKeypair(plen, qlen, label, getControl());
    finalize("DSA", objId);
    return null;
  }

}
