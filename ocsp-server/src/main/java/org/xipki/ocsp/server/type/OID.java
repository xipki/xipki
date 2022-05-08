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

package org.xipki.ocsp.server.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.CompareUtil;

import java.io.IOException;

/**
 * OID enums.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */
public enum OID {
  ID_PKIX_OCSP_NONCE(OCSPObjectIdentifiers.id_pkix_ocsp_nonce),
  ID_PKIX_OCSP_PREFSIGALGS(ObjectIdentifiers.Extn.id_pkix_ocsp_prefSigAlgs),
  ID_PKIX_OCSP_EXTENDEDREVOKE(ObjectIdentifiers.Extn.id_pkix_ocsp_extendedRevoke),
  ID_ISISMTT_AT_CERTHASH(ISISMTTObjectIdentifiers.id_isismtt_at_certHash),
  ID_INVALIDITY_DATE(Extension.invalidityDate),
  ID_PKIX_OCSP_ARCHIVE_CUTOFF(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff),
  ID_PKIX_OCSP_RESPONSE(OCSPObjectIdentifiers.id_pkix_ocsp_response);

  private final String id;

  private final byte[] encoded;

  OID(ASN1ObjectIdentifier oid) {
    this.id = oid.getId();
    try {
      this.encoded = oid.getEncoded();
    } catch (IOException ex) {
      throw new IllegalStateException("should not happen", ex);
    }
  }

  public String getId() {
    return id;
  }

  public int getEncodedLength() {
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
