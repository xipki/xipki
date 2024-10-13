// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.ocsp.server.type.ASN1Type;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.Extension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.security.CrlReason;

import java.time.Instant;

/**
 * OCSP response template.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

class ResponseTemplate {

  private static final byte[] extnInvalidityDate;

  private static final byte[] extnArchiveCutoff;

  private static final byte[] revokedInfoNoReasonPrefix = new byte[]{(byte) 0xA1, 0x11};

  private static final byte[] revokedInfoWithReasonPrefix = new byte[]{(byte) 0xA1, 0x16};

  private static final byte[] reasonPrefix = new byte[]{(byte) 0xa0, 0x03, 0x0a, 0x01};

  static {
    Extension extension = new ExtendedExtension(OID.ID_INVALIDITY_DATE, false, new byte[17]);
    extnInvalidityDate = new byte[extension.getEncodedLength()];
    extension.write(extnInvalidityDate, 0);

    extension = new ExtendedExtension(OID.ID_PKIX_OCSP_ARCHIVE_CUTOFF, false, new byte[17]);
    extnArchiveCutoff = new byte[extension.getEncodedLength()];
    extension.write(extnArchiveCutoff, 0);
  } // method static

  public static byte[] getEncodeRevokedInfo(CrlReason reason, Instant revocationTime) {
    byte[] encoded;
    if (reason == null) {
      encoded = new byte[19];
      System.arraycopy(revokedInfoNoReasonPrefix, 0, encoded, 0, 2);
      ASN1Type.writeGeneralizedTime(revocationTime, encoded, 2);
    } else {
      encoded = new byte[24];
      System.arraycopy(revokedInfoWithReasonPrefix, 0, encoded, 0, 2);
      ASN1Type.writeGeneralizedTime(revocationTime, encoded, 2);
      System.arraycopy(reasonPrefix, 0, encoded, 19, 4);
      encoded[23] = (byte) reason.getCode();
    }
    return encoded;
  } // method getEncodeRevokedInfo

}
