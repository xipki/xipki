// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.xipki.ocsp.server.type.ASN1Type;
import org.xipki.ocsp.server.type.CertID;
import org.xipki.ocsp.server.type.Extensions;
import org.xipki.ocsp.server.type.ResponderID;
import org.xipki.ocsp.server.type.ResponseData;
import org.xipki.ocsp.server.type.SingleResponse;
import org.xipki.ocsp.server.type.TaggedCertSequence;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.NoIdleSignerException;
import org.xipki.security.XiContentSigner;
import org.xipki.util.ConcurrentBag;
import org.xipki.util.Hex;

import java.io.IOException;
import java.io.OutputStream;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

/**
 * Generator for OCSP response objects.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OCSPRespBuilder {
  private static final byte[] successfulStatus = Hex.decode("0a0100");
  private static final byte[] responseTypeBasic = Hex.decode("06092b0601050507300101");

  private final List<SingleResponse> list = new LinkedList<>();
  private Extensions responseExtensions = null;
  private final ResponderID responderId;

  /**
   * basic constructor.
   *
   * @param responderId
   *          Responder ID
   */
  public OCSPRespBuilder(ResponderID responderId) {
    this.responderId = responderId;
  }

  /**
   * Add a response for a particular Certificate ID.
   *
   * @param certId certificate ID details
   * @param thisUpdate date this response was valid on
   * @param nextUpdate date when next update should be requested
   * @param certStatus status of the certificate - null if okay
   * @param singleExtensions optional extensions
   */
  public void addResponse(
      CertID certId, byte[] certStatus, Instant thisUpdate, Instant nextUpdate, Extensions singleExtensions) {
    list.add(new SingleResponse(certId, certStatus, thisUpdate, nextUpdate, singleExtensions));
  }

  /**
   * Set the extensions for the response.
   *
   * @param responseExtensions the extension object to carry.
   */
  public void setResponseExtensions(Extensions responseExtensions) {
    this.responseExtensions = responseExtensions;
  }

  public byte[] buildOCSPResponse(
      ConcurrentContentSigner signer, TaggedCertSequence taggedCertSequence, Instant producedAt)
      throws OCSPException, NoIdleSignerException {
    ResponseData responseData = new ResponseData(0, responderId, producedAt, list, responseExtensions);

    byte[] tbs = new byte[responseData.getEncodedLength()];
    responseData.write(tbs, 0);

    ConcurrentBag.BagEntry<XiContentSigner> signer0 = signer.borrowSigner();

    byte[] signature;
    byte[] sigAlgId;

    try {
      XiContentSigner csigner0 = signer0.value();
      OutputStream sigOut = csigner0.getOutputStream();
      try {
        sigOut.write(tbs);
        sigOut.close();
      } catch (IOException ex) {
        throw new OCSPException("exception signing TBSRequest: " + ex.getMessage(), ex);
      }

      signature = csigner0.getSignature();
      sigAlgId = csigner0.getEncodedAlgorithmIdentifier();
    } finally {
      signer.requiteSigner(signer0);
    }

    // ----- Get the length -----
    // BasicOCSPResponse.signature
    int signatureBodyLen = signature.length + 1;
    int signatureLen = getLen(signatureBodyLen);

    // BasicOCSPResponse
    int basicResponseBodyLen = tbs.length + sigAlgId.length + signatureLen;
    if (taggedCertSequence != null) {
      basicResponseBodyLen += taggedCertSequence.getEncodedLength();
    }
    int basicResponseLen = getLen(basicResponseBodyLen);

    // OCSPResponse.[0].responseBytes
    int responseBytesBodyLen = responseTypeBasic.length
        + getLen(basicResponseLen); // Header of OCTET STRING
    int responseBytesLen = getLen(responseBytesBodyLen);

    // OCSPResponse.[0]
    int taggedResponseBytesLen = getLen(responseBytesLen);

    // OCSPResponse
    int ocspResponseBodyLen = successfulStatus.length + taggedResponseBytesLen;
    int ocspResponseLen = getLen(ocspResponseBodyLen);

    // encode
    byte[] out = new byte[ocspResponseLen];
    int offset = 0;
    offset += ASN1Type.writeHeader((byte) 0x30, ocspResponseBodyLen, out, offset);
    // OCSPResponse.responseStatus
    offset += arraycopy(successfulStatus, out, offset);

    // OCSPResponse.[0]
    offset += ASN1Type.writeHeader((byte) 0xA0, responseBytesLen, out, offset);

    // OCSPResponse.[0]responseBytes
    offset += ASN1Type.writeHeader((byte) 0x30, responseBytesBodyLen, out, offset);

    // OCSPResponse.[0]responseBytes.responseType
    offset += arraycopy(responseTypeBasic, out, offset);

    // OCSPResponse.[0]responseBytes.responseType
    offset += ASN1Type.writeHeader((byte) 0x04, basicResponseLen, out, offset); // OCTET STRING

    // BasicOCSPResponse
    offset += ASN1Type.writeHeader((byte) 0x30, basicResponseBodyLen, out, offset);
    // BasicOCSPResponse.tbsResponseData
    offset += arraycopy(tbs, out, offset);

    // BasicOCSPResponse.signatureAlgorithm
    offset += arraycopy(sigAlgId, out, offset);

    // BasicOCSPResponse.signature
    offset += ASN1Type.writeHeader((byte) 0x03, signatureBodyLen, out, offset);
    out[offset++] = 0x00; // skipping bits
    offset += arraycopy(signature, out, offset);

    if (taggedCertSequence != null) {
      taggedCertSequence.write(out, offset);
    }
    return out;
  } // method buildOCSPResponse

  private static int getLen(int bodyLen) {
    return ASN1Type.getHeaderLen(bodyLen) + bodyLen;
  }

  private static int arraycopy(byte[] src, byte[] dest, int destPos) {
    System.arraycopy(src, 0, dest, destPos, src.length);
    return src.length;
  }

}
