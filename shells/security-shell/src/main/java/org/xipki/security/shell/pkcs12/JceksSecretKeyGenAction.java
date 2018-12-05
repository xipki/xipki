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

package org.xipki.security.shell.pkcs12;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.security.shell.SecurityCompleters;
import org.xipki.shell.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */
@Command(scope = "xi", name = "secretkey-p12",
    description = "generate secret key in JCEKS (not PKCS#12) keystore")
@Service
public class JceksSecretKeyGenAction extends P12KeyGenAction {

  @Option(name = "--key-type", required = true,
      description = "keytype, current only AES, DES3 and GENERIC are supported")
  @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
   private String keyType;

  @Option(name = "--key-size", required = true, description = "keysize in bit")
  private Integer keysize;

  @Override
  protected Object execute0() throws Exception {
    if (!("AES".equalsIgnoreCase(keyType) || "DES3".equalsIgnoreCase(keyType)
          || "GENERIC".equalsIgnoreCase(keyType))) {
      throw new IllegalCmdParamException("invalid keyType " + keyType);
    }

    P12KeyGenerationResult key = new P12KeyGenerator().generateSecretKey(
        keyType.toUpperCase(), keysize, getKeyGenParameters());
    saveKey(key);

    return null;
  }

}
