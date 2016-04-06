/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security.impl.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import org.xipki.commons.security.api.XiSecurityConstants;

/**
 *
 * Supported algorithms:<p/>
 *
 * Keystore
 * <ul>
 *   <li><code>PKCS11</code></li>
 * </ul>
 *
 * Signature (RSA)
 * <ul>
 *   <li><code>NONEwithRSA</code></li>
 *   <li><code>SHA1withRSA</code></li>
 *   <li><code>SHA224withRSA</code></li>
 *   <li><code>SHA256withRSA</code></li>
 *   <li><code>SHA384withRSA</code></li>
 *   <li><code>SHA512withRSA</code></li>
 *   <li><code>SHA1withRSAandMGF1</code></li>
 *   <li><code>SHA224withRSAandMGF1</code></li>
 *   <li><code>SHA256withRSAandMGF1</code></li>
 *   <li><code>SHA384withRSAandMGF1</code></li>
 *   <li><code>SHA512withRSAandMGF1</code></li>
 * </ul>
 *
 * Signature (DSA)
 * <ul>
 *   <li><code>NONEwithDSA</code></li>
 *   <li><code>SHA1withDSA</code></li>
 *   <li><code>SHA224withDSA</code></li>
 *   <li><code>SHA256withDSA</code></li>
 *   <li><code>SHA384withDSA</code></li>
 *   <li><code>SHA512withDSA</code></li>
 * </ul>
 *
 * Signature (ECDSA)
 * <ul>
 *   <li><code>NONEwithECDSA</code></li>
 *   <li><code>SHA1withECDSA</code></li>
 *   <li><code>SHA224withECDSA</code></li>
 *   <li><code>SHA256withECDSA</code></li>
 *   <li><code>SHA384withECDSA</code></li>
 *   <li><code>SHA512withECDSA</code></li>
 *   <li><code>NONEwithPlain-ECDSA</code></li>
 *   <li><code>SHA1withPlain-ECDSA</code></li>
 *   <li><code>SHA224withPlain-ECDSA</code></li>
 *   <li><code>SHA256withPlain-ECDSA</code></li>
 *   <li><code>SHA384withPlain-ECDSA</code></li>
 *   <li><code>SHA512withPlain-ECDSA</code></li>
 * </ul>
 *
 * @author Lijun Liao
 * @since 2.0.0
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
                    P11RSADigestSignatureSpi.NoneRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithNONE", "NONEwithRSA");

            provider.put("Signature.SHA1withRSA",
                    P11RSADigestSignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA1", "SHA1withRSA");

            provider.put("Signature.SHA224withRSA",
                    P11RSADigestSignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA224", "SHA224withRSA");

            provider.put("Signature.SHA256withRSA",
                    P11RSADigestSignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA256", "SHA256withRSA");

            provider.put("Signature.SHA384withRSA",
                    P11RSADigestSignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA384", "SHA384withRSA");

            provider.put("Signature.SHA512withRSA",
                    P11RSADigestSignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.RSAwithSHA512", "SHA512withRSA");

            provider.put("Signature.NONEwithDSA",
                    P11DSASignatureSpi.NONE.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithNONE", "NONEwithDSA");

            provider.put("Signature.SHA1withDSA",
                    P11DSASignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithSHA1", "SHA1withDSA");

            provider.put("Signature.SHA224withDSA",
                    P11DSASignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithSHA224", "SHA224withDSA");

            provider.put("Signature.SHA256withDSA",
                    P11DSASignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithSHA256", "SHA256withDSA");

            provider.put("Signature.SHA384withDSA",
                    P11ECDSASignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithSHA384", "SHA384withDSA");

            provider.put("Signature.SHA512withDSA",
                    P11DSASignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.DSAwithSHA512", "SHA512withDSA");

            provider.put("Signature.NONEwithECDSA",
                    P11ECDSASignatureSpi.NONE.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithNONE", "NONEwithECDSA");

            provider.put("Signature.SHA1withECDSA",
                    P11ECDSASignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA1", "SHA1withECDSA");

            provider.put("Signature.SHA224withECDSA",
                    P11ECDSASignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA224", "SHA224withECDSA");

            provider.put("Signature.SHA256withECDSA",
                    P11ECDSASignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA256", "SHA256withECDSA");

            provider.put("Signature.SHA384withECDSA",
                    P11ECDSASignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA384", "SHA384withECDSA");

            provider.put("Signature.SHA512withECDSA",
                    P11ECDSASignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.ECDSAwithSHA512", "SHA512withECDSA");

            provider.put("Signature.NONEwithPlain-ECDSA",
                    P11PlainECDSASignatureSpi.NONE.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithNONE", "NONEwithPlain-ECDSA");
            provider.put("Alg.Alias.Signature.NONEwithPlainECDSA", "NONEwithPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithNONE", "NONEwithPlain-ECDSA");

            provider.put("Signature.SHA1withPlain-ECDSA",
                    P11PlainECDSASignatureSpi.SHA1.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA1", "SHA1withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHAwithPlainECDSA1", "SHA1withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA1", "SHA1withPlain-ECDSA");

            provider.put("Signature.SHA224withPlain-ECDSA",
                    P11PlainECDSASignatureSpi.SHA224.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA224", "SHA224withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA224withPlainECDSA", "SHA224withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA224", "SHA224withPlain-ECDSA");

            provider.put("Signature.SHA256withPlain-ECDSA",
                    P11PlainECDSASignatureSpi.SHA256.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA256", "SHA256withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA256withPlainECDSA", "SHA256withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA256", "SHA256withPlain-ECDSA");

            provider.put("Signature.SHA384withPlain-ECDSA",
                    P11PlainECDSASignatureSpi.SHA384.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA384", "SHA384withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA384withPlainECDSA", "SHA384withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA384", "SHA384withPlain-ECDSA");

            provider.put("Signature.SHA512withPlain-ECDSA",
                    P11PlainECDSASignatureSpi.SHA512.class.getName());
            provider.put("Alg.Alias.Signature.Plain-ECDSAwithSHA512", "SHA512withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.SHA512withPlainECDSA", "SHA512withPlain-ECDSA");
            provider.put("Alg.Alias.Signature.PlainECDSAwithSHA512", "SHA512withPlain-ECDSA");

            provider.put("Signature.SHA1withRSAandMGF1",
                    P11RSAPSSSignatureSpi.SHA1withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA1", "SHA1withRSAandMGF1");

            provider.put("Signature.SHA224withRSAandMGF1",
                    P11RSAPSSSignatureSpi.SHA224withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA224", "SHA224withRSAandMGF1");

            provider.put("Signature.SHA256withRSAandMGF1",
                    P11RSAPSSSignatureSpi.SHA256withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA256", "SHA256withRSAandMGF1");

            provider.put("Signature.SHA384withRSAandMGF1",
                    P11RSAPSSSignatureSpi.SHA384withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA384", "SHA384withRSAandMGF1");

            provider.put("Signature.SHA512withRSAandMGF1",
                    P11RSAPSSSignatureSpi.SHA512withRSA.class.getName());
            provider.put("Alg.Alias.Signature.RSAandMGF1withSHA512", "SHA512withRSAandMGF1");

            return null;
        } // method run

    } // class MyPrivilegedAction

    /**
     * Exactly the name this provider is registered under at
     * <code>java.security.Security</code>: "<code>XiPKI</code>".
     */
    public static final String PROVIDER_NAME = XiSecurityConstants.PROVIDER_NAME_XIPKI;

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
    public XipkiProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        AccessController.doPrivileged(new MyPrivilegedAction(this));
    }

}
