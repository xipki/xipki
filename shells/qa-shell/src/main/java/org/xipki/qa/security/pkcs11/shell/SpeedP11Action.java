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

package org.xipki.qa.security.pkcs11.shell;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.qa.security.shell.SingleSpeedAction;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Hex;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class SpeedP11Action extends SingleSpeedAction {

  @Reference (optional = true)
  protected P11CryptServiceFactory p11CryptServiceFactory;

  @Option(name = "--key-id", description = "id of the PKCS#11 key")
  private String hexKeyId;

  @Option(name = "--slot", required = true, description = "slot index")
  protected Integer slotIndex;

  @Option(name = "--module", description = "Name of the PKCS#11 module.")
  @Completion(P11ModuleNameCompleter.class)
  protected String moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

  protected P11Slot getSlot()
      throws XiSecurityException, P11TokenException, IllegalCmdParamException {
    P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
    if (p11Service == null) {
      throw new IllegalCmdParamException("undefined module " + moduleName);
    }
    P11Module module = p11Service.getModule();
    return module.getSlot(module.getSlotIdForIndex(slotIndex));
  }

  protected byte[] getKeyId() {
    return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
  }

}
