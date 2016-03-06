/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.provider;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.xipki.commons.common.util.ParamUtil;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class RSAUtil {

    private static final ASN1ObjectIdentifier[] RSA_OIDS = {
        PKCSObjectIdentifiers.rsaEncryption,
        X509ObjectIdentifiers.id_ea_rsa,
        PKCSObjectIdentifiers.id_RSAES_OAEP,
        PKCSObjectIdentifiers.id_RSASSA_PSS
    };

    private RSAUtil() {
    }

    // CHECKSTYLE:SKIP
    public static boolean isRSAOid(
            final ASN1ObjectIdentifier algOid) {
        ParamUtil.requireNonNull("algOid", algOid);
        for (int i = 0; i != RSA_OIDS.length; i++) {
            if (algOid.equals(RSA_OIDS[i])) {
                return true;
            }
        }

        return false;
    }

    static RSAKeyParameters generatePublicKeyParameter(
            final RSAPublicKey key) {
        ParamUtil.requireNonNull("key", key);
        return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());

    }

    static RSAKeyParameters generatePrivateKeyParameter(
            final RSAPrivateKey key) {
        ParamUtil.requireNonNull("key", key);
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

            return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(),
                rsaKey.getPublicExponent(), rsaKey.getPrivateExponent(),
                rsaKey.getPrimeP(), rsaKey.getPrimeQ(), rsaKey.getPrimeExponentP(),
                rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
        } else {
            return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
        }
    }

}
