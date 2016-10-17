/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.security.bcbugfix;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class XipkiDigestAlgorithmIdentifierFinder extends DefaultDigestAlgorithmIdentifierFinder {

    public static final XipkiDigestAlgorithmIdentifierFinder INSTANCE
        = new XipkiDigestAlgorithmIdentifierFinder();

    private static Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> digestOids = new HashMap<>();

    static {
        // Plain-ECDSA
        digestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, OIWObjectIdentifiers.idSHA1);
        digestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, NISTObjectIdentifiers.id_sha224);
        digestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, NISTObjectIdentifiers.id_sha256);
        digestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, NISTObjectIdentifiers.id_sha384);
        digestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, NISTObjectIdentifiers.id_sha512);

        // RSA with SHA3
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
                NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
                NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
                NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
                NISTObjectIdentifiers.id_sha3_512);

        // DSA with SHA3
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_224,
                NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_256,
                NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_384,
                NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_512,
                NISTObjectIdentifiers.id_sha3_512);

        // ECDSA with SHA3
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224,
                NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256,
                NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384,
                NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512,
                NISTObjectIdentifiers.id_sha3_512);

    }

    @Override
    public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId) {
        ASN1ObjectIdentifier digOid = digestOids.get(sigAlgId.getAlgorithm());
        if (digOid != null) {
            return new AlgorithmIdentifier(digOid, DERNull.INSTANCE);
        }

        return super.find(sigAlgId);
    }

}
