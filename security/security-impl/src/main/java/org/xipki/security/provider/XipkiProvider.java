/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.security.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * @author Lijun Liao
 */

public class XipkiProvider extends Provider {

    @SuppressWarnings("rawtypes")
    private static class MyPrivilegedAction implements PrivilegedAction {

        private final XipkiProvider provider;

        MyPrivilegedAction(
                final XipkiProvider provider) {
            this.provider = provider;
        }

        @Override
        public Object run() {
            provider.put("KeyStore.PKCS11", XipkiKeyStoreSpi.class.getName());

            provider.put("Signature.NONEwithRSA",
                    RSADigestSignatureSpi.NoneRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithNONE", "NONEwithRSA");

            provider.put("Signature.SHA1withRSA",
                    RSADigestSignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA1", "SHA1withRSA");

            provider.put("Signature.SHA224withRSA",
                    RSADigestSignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA224", "SHA224withRSA");

            provider.put("Signature.SHA256withRSA",
                    RSADigestSignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA256", "SHA256withRSA");

            provider.put("Signature.SHA384withRSA",
                    RSADigestSignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA384", "SHA384withRSA");

            provider.put("Signature.SHA512withRSA",
                    RSADigestSignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA512", "SHA512withRSA");

            provider.put("Signature.RIPEMD160withRSA",
                    RSADigestSignatureSpi.RIPEMD160.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithRIPEMD160", "RIPEMD160withRSA");

            provider.put("Signature.RIPEMD256withRSA",
                    RSADigestSignatureSpi.RIPEMD256.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithRIPEMD256", "RIPEMD256withRSA");

            provider.put("Signature.NONEwithECDSA",
                    ECDSASignatureSpi.NONE.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithNONE", "NONEwithECDSA");

            provider.put("Signature.SHA1withECDSA",
                    ECDSASignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA1", "SHA1withECDSA");

            provider.put("Signature.SHA224withECDSA",
                    ECDSASignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA224", "SHA224withECDSA");

            provider.put("Signature.SHA256withECDSA",
                    ECDSASignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA256", "SHA256withECDSA");

            provider.put("Signature.SHA384withECDSA",
                    ECDSASignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA384", "SHA384withECDSA");

            provider.put("Signature.SHA512withECDSA",
                    ECDSASignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA512", "SHA512withECDSA");

            provider.put("Signature.RIPEMDwithECDSA",
                    ECDSASignatureSpi.RIPEMD160.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithRIPEMD160", "RIPEMD160withECDSA");

            provider.put("Signature.NONEwithPlain-ECDSA",
                    PlainECDSASignatureSpi.NONE.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithNONE", "NONEwithPlain-ECDSA");
            provider.put("Alg.Alias.Signature.NONEwithPlainECDSA",  "NONEwithPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithNONE",  "NONEwithPlain-ECDSA");

            provider.put("Signature.SHA1withPlain-ECDSA",
                    PlainECDSASignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA1", "SHA1withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHAwithPlainECDSA1",  "SHA1withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA1",  "SHA1withPlain-ECDSA");

            provider.put("Signature.SHA224withPlain-ECDSA",
                    PlainECDSASignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA224", "SHA224withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA224withPlainECDSA",  "SHA224withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA224",  "SHA224withPlain-ECDSA");

            provider.put("Signature.SHA256withPlain-ECDSA",
                    PlainECDSASignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA256", "SHA256withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA256withPlainECDSA",  "SHA256withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA256",  "SHA256withPlain-ECDSA");

            provider.put("Signature.SHA384withPlain-ECDSA",
                    PlainECDSASignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA384", "SHA384withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA384withPlainECDSA",  "SHA384withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA384",  "SHA384withPlain-ECDSA");

            provider.put("Signature.SHA512withPlain-ECDSA",
                    PlainECDSASignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA512", "SHA512withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA512withPlainECDSA",  "SHA512withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA512",  "SHA512withPlain-ECDSA");

            provider.put("Signature.RIPEMD160withPlain-ECDSA",
                    PlainECDSASignatureSpi.RIPEMD160.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithRIPEMD160",
                    "RIPEMD160withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.RIPEMD160withPlainECDSA",
                    "RIPEMD160withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithRIPEMD160",
                    "RIPEMD160withPlain-ECDSA");

            provider.put("Signature.SHA1withRSAandMGF1",
                    RSAPSSSignatureSpi.SHA1withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA1", "SHA1withRSAandMGF1");

            provider.put("Signature.SHA224withRSAandMGF1",
                    RSAPSSSignatureSpi.SHA224withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA224", "SHA224withRSAandMGF1");

            provider.put("Signature.SHA256withRSAandMGF1",
                    RSAPSSSignatureSpi.SHA256withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA256", "SHA256withRSAandMGF1");

            provider.put("Signature.SHA384withRSAandMGF1",
                    RSAPSSSignatureSpi.SHA384withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA384", "SHA384withRSAandMGF1");

            provider.put("Signature.SHA512withRSAandMGF1",
                    RSAPSSSignatureSpi.SHA512withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA512", "SHA512withRSAandMGF1");

            return null;
        }

    } // class MyPrivilegedAction

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
    public XipkiProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        AccessController.doPrivileged(new MyPrivilegedAction(this));
    }

}
