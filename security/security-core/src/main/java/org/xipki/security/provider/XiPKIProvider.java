/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class XiPKIProvider extends Provider
{
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
      public static final double PROVIDER_VERSION = 1.0;

      /**
       * An informational text giving the name and the version of this provider
       * and also telling about the provided algorithms.
       */
      private static final String PROVIDER_INFO = "XiPKI JCA/JCE provider";

      @SuppressWarnings("unchecked")
      public XiPKIProvider()
      {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        AccessController.doPrivileged(new MyPrivilegedAction(this));
      }

      @SuppressWarnings("rawtypes")
      private static class MyPrivilegedAction implements PrivilegedAction
      {
           private final XiPKIProvider provider;
           MyPrivilegedAction(XiPKIProvider provider)
           {
               this.provider = provider;
           }

           @Override
           public Object run()
           {
               provider.put("KeyStore.PKCS11", XiPKIKeyStoreSpi.class.getName());

               provider.put("Signature.NONEwithRSA", RSADigestSignatureSpi.noneRSA.class.getName());
               provider.put("Signature.SHA1withRSA", RSADigestSignatureSpi.SHA1.class.getName());
               provider.put("Signature.SHA224withRSA", RSADigestSignatureSpi.SHA224.class.getName());
               provider.put("Signature.SHA256withRSA", RSADigestSignatureSpi.SHA256.class.getName());
               provider.put("Signature.SHA384withRSA", RSADigestSignatureSpi.SHA384.class.getName());
               provider.put("Signature.SHA512withRSA", RSADigestSignatureSpi.SHA512.class.getName());
               provider.put("Signature.RIPEMD160withRSA", RSADigestSignatureSpi.RIPEMD160.class.getName());
               provider.put("Signature.RIPEMD256withRSA", RSADigestSignatureSpi.RIPEMD256.class.getName());

               provider.put("Signature.NONEwithECDSA", ECDSASignatureSpi.NONE.class.getName());
               provider.put("Signature.SHA1withECDSA", ECDSASignatureSpi.SHA1.class.getName());
               provider.put("Signature.SHA224withECDSA", ECDSASignatureSpi.SHA224.class.getName());
               provider.put("Signature.SHA256withECDSA", ECDSASignatureSpi.SHA256.class.getName());
               provider.put("Signature.SHA384withECDSA", ECDSASignatureSpi.SHA384.class.getName());
               provider.put("Signature.SHA512withECDSA", ECDSASignatureSpi.SHA512.class.getName());
               provider.put("Signature.RIPEMDwithECDSA", ECDSASignatureSpi.RIPEMD160.class.getName());

               provider.put("Signature.SHA1withRSAandMGF1", RSAPSSSignatureSpi.SHA1withRSA.class.getName());
               provider.put("Signature.SHA224withRSAandMGF1", RSAPSSSignatureSpi.SHA224withRSA.class.getName());
               provider.put("Signature.SHA256withRSAandMGF1", RSAPSSSignatureSpi.SHA256withRSA.class.getName());
               provider.put("Signature.SHA384withRSAandMGF1", RSAPSSSignatureSpi.SHA384withRSA.class.getName());
               provider.put("Signature.SHA512withRSAandMGF1", RSAPSSSignatureSpi.SHA512withRSA.class.getName());

               return null;
          }
     }
}
