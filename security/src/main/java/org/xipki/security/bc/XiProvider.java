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

package org.xipki.security.bc;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The XIPKI Provider class.
 * Supported algorithms:
 *
 * <p>Signature (RSAPSS)
 * <ul>
 *   <li><code>SHAKE128WITHRSAPSS</code></li>
 *   <li><code>1.3.6.1.5.5.7.6.30</code></li>
 *   <li><code>SHAKE256WITHRSAPSS</code></li>
 *   <li><code>1.3.6.1.5.5.7.6.31</code></li>
 * </ul>
 *
 * <p>Signature (ECDSA)
 * <ul>
 *   <li><code>SHAKE128WITHECDSA</code></li>
 *   <li><code>1.3.6.1.5.5.7.6.32</code></li>
 *   <li><code>SHAKE256WITHECDSA</code></li>
 *   <li><code>1.3.6.1.5.5.7.6.33</code></li>
 * </ul>
 *
 * @author Lijun Liao
 */

public class XiProvider extends Provider {

  @SuppressWarnings("rawtypes")
  private static class MyPrivilegedAction implements PrivilegedAction {

    private final XiProvider provider;

    MyPrivilegedAction(XiProvider provider) {
      this.provider = provider;
    }

    @Override
    public Object run() {
      provider.put("Signature.SHAKE128WITHRSAPSS",
          ShakePSSSignatureSpi.SHAKE128.class.getName());
      provider.put("Alg.Alias.Signature.RSAPSSWITHSHAKE128", "SHAKE128WITHRSAPSS");
      provider.put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.30", "SHAKE128WITHRSAPSS");

      provider.put("Signature.SHAKE256WITHRSAPSS",
          ShakePSSSignatureSpi.SHAKE256.class.getName());
      provider.put("Alg.Alias.Signature.RSAPSSWITHSHAKE256", "SHAKE256WITHRSAPSS");
      provider.put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.31", "SHAKE256WITHRSAPSS");

      provider.put("Signature.SHAKE128WITHECDSA",
          ShakeECDSASignatureSpi.SHAKE128.class.getName());
      provider.put("Alg.Alias.Signature.ECDSAWITHSHAKE128",  "SHAKE128WITHECDSA");
      provider.put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.32", "SHAKE128WITHECDSA");

      provider.put("Signature.SHAKE256WITHECDSA",
          ShakeECDSASignatureSpi.SHAKE256.class.getName());
      provider.put("Alg.Alias.Signature.ECDSAWITHSHAKE256",  "SHAKE256WITHECDSA");
      provider.put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.33", "SHAKE256WITHECDSA");

      return null;
    } // method run

  } // class MyPrivilegedAction

  /**
   * Exactly the name this provider is registered under at
   * <code>java.security.Security</code>: "<code>XIPKI</code>".
   */
  public static final String PROVIDER_NAME = "XIPKI";

  /**
   * Version of this provider as registered at
   * <code>java.security.Security</code>.
   */
  public static final double PROVIDER_VERSION = 1.0;

  /**
   * An informational text giving the name and the version of this provider
   * and also telling about the provided algorithms.
   */
  private static final String PROVIDER_INFO = "XiPKI JCA/JCE provider";

  private static final long serialVersionUID = 1L;

  @SuppressWarnings("unchecked")
  public XiProvider() {
    super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
    AccessController.doPrivileged(new MyPrivilegedAction(this));
  }

}
