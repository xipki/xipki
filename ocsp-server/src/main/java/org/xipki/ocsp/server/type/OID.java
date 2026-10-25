// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.OcspOIDs;
import org.xipki.pkix.util.misc.CompareUtil;

/**
 * OID enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum OID {
  ID_PKIX_OCSP_NONCE(OcspOIDs.id_pkix_ocsp_nonce),
  ID_PKIX_OCSP_PREFSIGALGS(ExtensionOIDs.id_pkix_ocsp_prefSigAlgs),
  ID_PKIX_OCSP_EXTENDEDREVOKE(ExtensionOIDs.id_pkix_ocsp_extendedRevoke),
  ID_ISISMTT_AT_CERTHASH(ExtensionOIDs.isismtt_at_certHash),

  ID_INVALIDITY_DATE(ExtensionOIDs.invalidityDate),
  ID_PKIX_OCSP_ARCHIVE_CUTOFF(OcspOIDs.id_pkix_ocsp_archive_cutoff),
  ID_PKIX_OCSP_RESPONSE(OcspOIDs.id_pkix_ocsp_response);

  private final String id;

  private final byte[] encoded;

  OID(Asn1Oid oid) {
    this.id = oid.getId();
    this.encoded = oid.getEncoded();
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
