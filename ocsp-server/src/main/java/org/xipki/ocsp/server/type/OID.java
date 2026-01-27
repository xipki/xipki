// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.extra.misc.CompareUtil;

import java.io.IOException;

/**
 * OID enums.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public enum OID {
  ID_PKIX_OCSP_NONCE(OIDs.OCSP.id_pkix_ocsp_nonce),
  ID_PKIX_OCSP_PREFSIGALGS(OIDs.Extn.id_pkix_ocsp_prefSigAlgs),
  ID_PKIX_OCSP_EXTENDEDREVOKE(OIDs.Extn.id_pkix_ocsp_extendedRevoke),
  ID_ISISMTT_AT_CERTHASH(OIDs.Misc.isismtt_at_certHash),

  ID_INVALIDITY_DATE(OIDs.Extn.invalidityDate),
  ID_PKIX_OCSP_ARCHIVE_CUTOFF(OIDs.OCSP.id_pkix_ocsp_archive_cutoff),
  ID_PKIX_OCSP_RESPONSE(OIDs.OCSP.id_pkix_ocsp_response);

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
