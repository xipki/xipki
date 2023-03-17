// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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
 * @author Lijun Liao (xipki)
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

    KeypairGenerator kpGen = TYPE_SOFTWARE.equalsIgnoreCase(type)
        ? new SoftwareKeypairGenerator(securityFactory.getRandom4Key())
        : new P11KeypairGenerator(p11CryptServiceFactory);

    try {
      kpGen.initialize(conf, securityFactory.getPasswordResolver());
    } catch (XiSecurityException ex) {
      throw new ObjectCreationException("error initializing keypairGen", ex);
    }
    return kpGen;
  }

}
