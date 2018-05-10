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
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "rsa-p11",
    description = "generate RSA keypair in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11RSAKeyGenAction extends P11KeyGenAction {

  @Option(name = "--key-size",
      description = "keysize in bit")
  private Integer keysize = 2048;

  @Option(name = "-e",
      description = "public exponent")
  private String publicExponent = "0x10001";

  @Override
  protected Object execute0() throws Exception {
    if (keysize % 1024 != 0) {
      throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
    }

    P11Slot slot = getSlot();
    P11ObjectIdentifier objId = slot.generateRSAKeypair(keysize, toBigInt(publicExponent),
        label, getControl());
    finalize("RSA", objId);
    return null;
  }

  @Override
  protected boolean getDefaultExtractable() {
    return false;
  }

}
