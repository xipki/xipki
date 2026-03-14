// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.provider;

import org.xipki.security.OIDs;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class XiPKIProvider extends Provider {

  private static final long serialVersionUID = 1L;

  /**
   * Exactly the name this provider is registered under at
   * <code>java.security.Security</code>: "<code>XiPKI</code>".
   */
  public static final String PROVIDER_NAME = "XiPKI";

  /**
   * Version of this provider as registered at
   * <code>java.security.Security</code>.
   */
  public static final String PROVIDER_VERSION = "1.0";

  /**
   * An informational text giving the name and the version of this provider
   * and also telling about the provided algorithms.
   */
  private static final String PROVIDER_INFO = "XiPKI JCA/JCE provider";

  public XiPKIProvider(boolean withSM2, boolean withRsaPssShake) {
    super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
    AccessController.doPrivileged(new MyPrivilegedAction(this, withSM2, withRsaPssShake));
  }

  private static class MyPrivilegedAction implements PrivilegedAction<MyPrivilegedAction> {

    private final XiPKIProvider provider;
    private final boolean withSM2;
    private final boolean withRsaPssShake;

    MyPrivilegedAction(XiPKIProvider provider, boolean withSM2, boolean withRsaPssShake) {
      this.provider = provider;
      this.withSM2  = withSM2;
      this.withRsaPssShake = withRsaPssShake;
    }

    @Override
    public MyPrivilegedAction run() {
      if (withSM2) {
        provider.put("MessageDigest.SM3", SM3MessageDigestSpi.class.getName());
        String id_sm3 = OIDs.Algo.id_sm3.getId();
        provider.put("Alg.Alias.MessageDigest." + id_sm3, "SM3");

        String sm2withsm3Impl = SM2WITHSM3SignatureSpi.class.getName();
        provider.put("Signature.SM2WITHSM3", sm2withsm3Impl);
        provider.put("Alg.Alias.Signature.SM3WITHSM2", "SM2WITHSM3");
        String id_sm2sign_with_sm3 = OIDs.Algo.sm2sign_with_sm3.getId();
        provider.put("Alg.Alias.Signature." + id_sm2sign_with_sm3, "SM2WITHSM3");
      }

      if (withRsaPssShake) {
        String rsashake128Impl = RSAPSSSHAKESignatureSpi.RSAPSSSHAKE128.class.getName();
        provider.put("Signature.SHAKE128WITHRSAPSS", rsashake128Impl);
        provider.put("Alg.Alias.Signature.RSAPSSWITHSHAKE128", "SHAKE128WITHRSAPSS");

        String rsashake256Impl = RSAPSSSHAKESignatureSpi.RSAPSSSHAKE256.class.getName();
        provider.put("Signature.SHAKE256WITHRSAPSS", rsashake256Impl);
        provider.put("Alg.Alias.Signature.RSAPSSWITHSHAKE256", "SHAKE256WITHRSAPSS");
      }
      return this;
    }
  }
}
