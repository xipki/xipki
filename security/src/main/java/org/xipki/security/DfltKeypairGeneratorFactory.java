/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.security;

import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11KeypairGenerator;
import org.xipki.security.pkcs12.SoftwareKeypairGenerator;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * {@link KeypairGeneratorFactory} for the type software.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class DfltKeypairGeneratorFactory implements KeypairGeneratorFactory {

  private static final String TYPE_SOFTWARE = "software";

  private static final String TYPE_PKCS11 = "pkcs11";

  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList(TYPE_SOFTWARE, TYPE_PKCS11)));

  private P11CryptServiceFactory p11CryptServiceFactory;

  private SecurityFactory securityFactory;

  public void setP11CryptServiceFactory(P11CryptServiceFactory p11CryptServiceFactory) {
    this.p11CryptServiceFactory = p11CryptServiceFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  @Override
  public Set<String> getSupportedKeypairTypes() {
    return types;
  }

  @Override
  public boolean canCreateKeypairGenerator(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public KeypairGenerator newKeypairGenerator(String type, String conf, SecurityFactory securityFactory)
      throws ObjectCreationException {
    if (!canCreateKeypairGenerator(type)) {
      throw new ObjectCreationException("unknown keypair generator type " + type);
    }

    KeypairGenerator kpGen;
    if (TYPE_SOFTWARE.equalsIgnoreCase(type)) {
      kpGen = new SoftwareKeypairGenerator(securityFactory.getRandom4Key());
    } else { //if (TYPE_PKCS11.equalsIgnoreCase(type)) {
      kpGen = new P11KeypairGenerator(p11CryptServiceFactory);
    }
    try {
      kpGen.initialize(conf, securityFactory.getPasswordResolver());
    } catch (XiSecurityException ex) {
      throw new ObjectCreationException("error initializing keypairGen", ex);
    }
    return kpGen;
  }

}
