/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs11.provider;

import org.xipki.security.pkcs11.P11CryptServiceFactory;

import java.security.Security;

/**
 * Helper class to register the {@link XiPkcs11Provider}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XiProviderRegister {

  public void regist() {
    if (Security.getProperty(XiPkcs11Provider.PROVIDER_NAME) == null) {
      Security.addProvider(new XiPkcs11Provider());
    }
  }

  public void setP11CryptServiceFactory(P11CryptServiceFactory p11CryptServiceFactory) {
    XiKeyStoreSpi.setP11CryptServiceFactory(p11CryptServiceFactory);
  }

}
