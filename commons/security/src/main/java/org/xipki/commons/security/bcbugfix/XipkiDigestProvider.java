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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.bc.BcDigestProvider;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class XipkiDigestProvider implements BcDigestProvider {
    private static final BcDigestProvider underlyingDigestProvider =
            BcDefaultDigestProvider.INSTANCE;
    private static final Map<ASN1ObjectIdentifier, BcDigestProvider> lookup = createTable();

    private static Map<ASN1ObjectIdentifier, BcDigestProvider> createTable() {
        Map<ASN1ObjectIdentifier, BcDigestProvider> table = new HashMap<>();

        table.put(NISTObjectIdentifiers.id_sha3_224, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA3Digest(224);
            }
        });

        table.put(NISTObjectIdentifiers.id_sha3_256, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA3Digest(256);
            }
        });

        table.put(NISTObjectIdentifiers.id_sha3_384, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA3Digest(384);
            }
        });

        table.put(NISTObjectIdentifiers.id_sha3_512, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA3Digest(512);
            }
        });

        return Collections.unmodifiableMap(table);
    }

    public static final BcDigestProvider INSTANCE = new XipkiDigestProvider();

    private XipkiDigestProvider() {
    }

    public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
    throws OperatorCreationException {
        BcDigestProvider extProv = (BcDigestProvider)
                lookup.get(digestAlgorithmIdentifier.getAlgorithm());

        if (extProv != null) {
            return extProv.get(digestAlgorithmIdentifier);
        }

        return underlyingDigestProvider.get(digestAlgorithmIdentifier);
    }
}
