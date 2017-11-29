/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ocsp.server.impl.type;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.common.ASN1Type;
import org.xipki.common.util.CompareUtil;
import org.xipki.security.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public enum OID {
    ID_PKIX_OCSP_NONCE (OCSPObjectIdentifiers.id_pkix_ocsp_nonce),
    ID_PKIX_OCSP_PREFSIGALGS (ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs),
    ID_PKIX_OCSP_EXTENDEDREVOKE (ObjectIdentifiers.id_pkix_ocsp_extendedRevoke),
    ID_ISISMTT_AT_CERTHASH (ISISMTTObjectIdentifiers.id_isismtt_at_certHash),
    ID_INVALIDITY_DATE(Extension.invalidityDate),
    ID_PKIX_OCSP_ARCHIVE_CUTOFF (OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);

    private String id;

    private byte[] encoded;

    private OID(ASN1ObjectIdentifier oid) {
        this.id = oid.getId();
        try {
            this.encoded = oid.getEncoded();
        } catch (IOException ex) {
            throw new IllegalStateException("should not happen", ex);
        }
    }

    public String id() {
        return id;
    }

    public int encodedLength() {
        return encoded.length;
    }

    public int write(byte[] out, int offset) {
        return ASN1Type.arraycopy(encoded, out, offset);
    }

    public static OID getInstanceForEncoded(byte[] data, int offset) {
        for (OID m : OID.values()) {
            if (CompareUtil.areEqual(data, offset, m.encoded, 0, m.encoded.length)) {
                return m;
            }
        }
        return null;
    }

}
