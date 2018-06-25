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
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.shell.completer.ECCurveNameCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "ec-p11", description = "generate EC keypair in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11ECKeyGenAction extends P11KeyGenAction {

  @Option(name = "--curve", description = "EC curve name")
  @Completion(ECCurveNameCompleter.class)
  private String curveName = "secp256r1";

  @Override
  protected Object execute0() throws Exception {
    P11Slot slot = getSlot();
    P11IdentityId identityId = slot.generateECKeypair(curveName, getControl());
    finalize("EC", identityId);
    return null;
  }

}
