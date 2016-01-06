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

package org.xipki.security;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Lijun Liao
 */

public abstract class P12RawKeypairGenerator {
    public abstract KeyPair genKeypair()
    throws Exception;

    public P12RawKeypairGenerator()
    throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static class ECKeypairGenerator extends P12RawKeypairGenerator {
        private final String curveName;
        private final ASN1ObjectIdentifier curveOid;

        public ECKeypairGenerator(
                final String curveNameOrOid)
        throws Exception {
            super();

            boolean isOid;
            try {
                new ASN1ObjectIdentifier(curveNameOrOid);
                isOid = true;
            } catch (Exception e) {
                isOid = false;
            }

            if (isOid) {
                this.curveOid = new ASN1ObjectIdentifier(curveNameOrOid);
                this.curveName =  KeyUtil.getCurveName(this.curveOid);
            } else {
                this.curveName = curveNameOrOid;
                this.curveOid =  KeyUtil.getCurveOID(this.curveName);
                if (this.curveOid == null) {
                    throw new IllegalArgumentException("no OID is defined for the curve "
                            + this.curveName);
                }
            }
        }

        @Override
        public KeyPair genKeypair()
        throws Exception {
            return KeyUtil.generateECKeypair(this.curveOid);
        }

    }

    public static class RSAKeypairGenerator extends P12RawKeypairGenerator {
        private final int keysize;
        private final BigInteger publicExponent;

        public RSAKeypairGenerator(
                final int keysize,
                final BigInteger publicExponent)
        throws Exception {
            super();

            this.keysize = keysize;
            this.publicExponent = publicExponent;
        }

        @Override
        public KeyPair genKeypair()
        throws Exception {
            return KeyUtil.generateRSAKeypair(keysize, publicExponent);
        }

    }

    public static class DSAKeypairGenerator extends P12RawKeypairGenerator {
        private final int pLength;
        private final int qLength;

        public DSAKeypairGenerator(
                final int pLength,
                final int qLength)
        throws Exception {
            super();

            this.pLength = pLength;
            this.qLength = qLength;
        }

        @Override
        public KeyPair genKeypair()
        throws Exception {
            return KeyUtil.generateDSAKeypair(pLength, qLength);
        }

    }

}
