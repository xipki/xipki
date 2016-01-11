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

package org.xipki.security.speed.p12;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.KeyUtil;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class P12SignLoadTest extends LoadExecutor {

    class Testor implements Runnable {

        @Override
        public void run() {
            ContentSigner singleSigner;
            try {
                singleSigner = signer.borrowContentSigner();
            } catch (NoIdleSignerException e) {
                account(1, 1);
                return;
            }

            while (!stop() && getErrorAccout() < 1) {
                try {
                    singleSigner.getOutputStream().write(new byte[]{1, 2, 3, 4});
                    singleSigner.getSignature();
                    account(1, 0);
                } catch (Exception e) {
                    account(1, 1);
                }
            }

            signer.returnContentSigner(singleSigner);
        }

    } // class Testor

    private final ConcurrentContentSigner signer;

    protected final static String password = "1234";

    public P12SignLoadTest(
            final SecurityFactory securityFactory,
            final String signatureAlgorithm,
            final byte[] keystore,
            final String description)
    throws Exception {
        super(description);

        ParamUtil.assertNotNull("securityFactory", securityFactory);
        ParamUtil.assertNotBlank("signatureAlgorithm", signatureAlgorithm);
        ParamUtil.assertNotNull("keystore", keystore);

        String signerConf = SecurityFactoryImpl.getKeystoreSignerConf(
                new ByteArrayInputStream(keystore), password, signatureAlgorithm, 20);
        this.signer = securityFactory.createSigner("PKCS12", signerConf, (X509Certificate) null);
    }

    @Override
    protected Runnable getTestor()
    throws Exception {
        return new Testor();
    }

    protected static byte[] getPrecomputedRSAKeystore(
            final int keysize,
            final BigInteger publicExponent)
    throws IOException {
        return getPrecomputedKeystore("rsa-" + keysize + "-0x" + publicExponent.toString(16)
            + ".p12");
    }

    protected static byte[] getPrecomputedDSAKeystore(
            final int pLength,
            final int qLength)
    throws IOException {
        return getPrecomputedKeystore("dsa-" + pLength + "-" + qLength + ".p12");
    }

    protected static byte[] getPrecomputedECKeystore(
            final String curveNamOrOid)
    throws IOException {
        ASN1ObjectIdentifier oid = null;
        try {
            new ASN1ObjectIdentifier(curveNamOrOid);
        } catch (Exception e) {
            oid = KeyUtil.getCurveOID(curveNamOrOid);
        }
        if (oid == null) {
            return null;
        }

        return getPrecomputedKeystore("ec-" + oid.getId() + ".p12");
    }

    private static byte[] getPrecomputedKeystore(
            final String filename)
    throws IOException {
        InputStream in = P12ECSignLoadTest.class.getResourceAsStream("/testkeys/" + filename);
        return (in == null)
                ? null
                : IoUtil.read(in);
    }

}
