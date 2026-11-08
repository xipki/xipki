// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.xipki.pkix.asn1.ocsp.OCSPRequest;
import org.xipki.pkix.asn1.ocsp.Request;
import org.xipki.pkix.asn1.ocsp.TBSRequest;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.ocsp.api.RequestIssuer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * OCSP Request payload.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspRequest {

  static class Header {
    final int tagIndex;
    final byte tag;
    final int len;
    final int readerIndex;

    Header(int tagIndex, byte tag, int len, int readerIndex) {
      this.tagIndex = tagIndex;
      this.tag = tag;
      this.len = len;
      this.readerIndex = readerIndex;
    }

    int end() {
      return readerIndex + len;
    }

    @Override
    public String toString() {
      return "tag=0x" + Integer.toHexString(0xFF & tag) + ", len=" + len
          + ", tagIndex=" + tagIndex + ", readerIndex=" + readerIndex;
    }
  }

  private static final byte TAG_INTEGER = 0x02;
  private static final byte TAG_OCTET_STRING = 0x04;
  private static final byte TAG_SEQUENCE = 0x30;
  private static final byte TAG_CTX_0 = (byte) 0xA0;
  private static final byte TAG_CTX_1 = (byte) 0xA1;
  private static final byte TAG_CTX_2 = (byte) 0xA2;

  private final int version;

  private final List<ExtendedExtension> extensions;

  private final List<CertID> requestList;

  public OcspRequest(int version, List<CertID> requestList, List<ExtendedExtension> extensions) {
    this.version = version;
    this.requestList = requestList;
    this.extensions = extensions;
  }

  public static OcspRequest getInstance(byte[] request) throws EncodingException {
    try {
      return getInstance0(request);
    } catch (RuntimeException ex) {
      // e.g. IndexOutOfBoundsException caused by a malformed request.
      throw new EncodingException("malformed request: " + ex.getMessage(), ex);
    }
  }

  private static OcspRequest getInstance0(byte[] request) throws EncodingException {
    // OCSPRequest
    Header hdrReq = readHeader(request, 0, request.length, TAG_SEQUENCE);
    if (hdrReq.end() != request.length) {
      throw new EncodingException("trailing data after OCSPRequest");
    }

    // tbsRequest
    Header hdrTbs = readHeader(request, hdrReq.readerIndex, hdrReq.end(), TAG_SEQUENCE);
    final int tbsEnd = hdrTbs.end();

    // optionalSignature
    if (tbsEnd < hdrReq.end()) {
      Header hdrSig = readHeader(request, tbsEnd, hdrReq.end(), TAG_CTX_0);
      if (hdrSig.end() != hdrReq.end()) {
        throw new EncodingException("trailing data after optionalSignature");
      }
    }

    int version = 0;

    // First element of the tbsRequest
    Header hdr = readHeader(request, hdrTbs.readerIndex, tbsEnd);
    if (hdr.tag == TAG_CTX_0) {
      Header hdr0 = readHeader(request, hdr.readerIndex, hdr.end(), TAG_INTEGER);
      if (hdr0.len != 1 || hdr0.end() != hdr.end()) {
        throw new EncodingException("version too large");
      }
      version = 0xFF & request[hdr0.readerIndex];
      hdr = readHeader(request, hdr.end(), tbsEnd);
    }

    // requestorName
    if (hdr.tag == TAG_CTX_1) {
      hdr = readHeader(request, hdr.end(), tbsEnd);
    }

    Header hdrRequestList = hdr;
    if (hdrRequestList.tag != TAG_SEQUENCE) {
      throw new EncodingException("requestList is not a SEQUENCE");
    }
    if (hdrRequestList.len == 0) {
      throw new EncodingException("requestList is empty");
    }

    // requestList
    List<CertID> requestList = new LinkedList<>();
    int offset = hdrRequestList.readerIndex;
    while (offset < hdrRequestList.end()) {
      Header hdrSingleReq = readHeader(request, offset, hdrRequestList.end(), TAG_SEQUENCE);
      requestList.add(readCertId(request, hdrSingleReq));
      offset = hdrSingleReq.end();
    }

    // extensions
    List<ExtendedExtension> extensions = new LinkedList<>();
    if (hdrRequestList.end() < tbsEnd) {
      hdr = readHeader(request, hdrRequestList.end(), tbsEnd, TAG_CTX_2);
      if (hdr.end() != tbsEnd) {
        throw new EncodingException("trailing data in tbsRequest");
      }

      Header hdrExtensions = readHeader(request, hdr.readerIndex, hdr.end(), TAG_SEQUENCE);
      if (hdrExtensions.end() != hdr.end()) {
        throw new EncodingException("trailing data after requestExtensions");
      }

      offset = hdrExtensions.readerIndex;
      while (offset < hdrExtensions.end()) {
        Header hdrExtension = readHeader(request, offset, hdrExtensions.end(), TAG_SEQUENCE);
        ExtendedExtension extn = ExtendedExtension.getInstance(request, hdrExtension.tagIndex,
            hdrExtension.end() - hdrExtension.tagIndex);
        if (extn != null) {
          extensions.add(extn);
        }
        offset = hdrExtension.end();
      }
    }

    return new OcspRequest(version, requestList, extensions);
  } // method getInstance

  private static CertID readCertId(byte[] request, Header hdrSingleReq) throws EncodingException {
    final int reqEnd = hdrSingleReq.end();
    Header hdrCertId = readHeader(request, hdrSingleReq.readerIndex, reqEnd, TAG_SEQUENCE);
    final int end = hdrCertId.end();

    // singleRequestExtensions
    if (end < reqEnd) {
      Header hdrExtns = readHeader(request, end, reqEnd, TAG_CTX_0);
      if (hdrExtns.end() != reqEnd) {
        throw new EncodingException("trailing data in Request");
      }
    }

    Header hdrHashAlgo = readHeader(request, hdrCertId.readerIndex, end, TAG_SEQUENCE);
    Header hdrNameHash = readHeader(request, hdrHashAlgo.end(), end, TAG_OCTET_STRING);
    Header hdrKeyHash  = readHeader(request, hdrNameHash.end(), end, TAG_OCTET_STRING);
    Header hdrSerial   = readHeader(request, hdrKeyHash.end(), end, TAG_INTEGER);
    if (hdrSerial.end() != end) {
      throw new EncodingException("trailing data in CertID");
    }

    if (hdrSerial.len == 0) {
      throw new EncodingException("serialNumber is empty");
    }
    if (request[hdrSerial.readerIndex] < 0) {
      throw new EncodingException("serialNumber is negative");
    }

    RequestIssuer issuer;
    try {
      issuer = new RequestIssuer(request, hdrCertId.readerIndex,
          hdrKeyHash.end() - hdrCertId.readerIndex);
    } catch (NoSuchAlgorithmException ex) {
      throw new EncodingException(ex);
    }

    return new CertID(issuer, new BigInteger(readContent(request, hdrSerial)));
  }

  public static OcspRequest getInstance(OCSPRequest req) throws EncodingException {
    TBSRequest tbsReq = req.getTbsRequest();

    Extensions extensions0 = tbsReq.getRequestExtensions();
    Request.Seq0 requestList0 = tbsReq.getRequestList();

    final int n = requestList0.size();
    if (n == 0) {
      throw new EncodingException("requestList is empty");
    }
    List<CertID> requestList = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      Request singleReq0 = requestList0.get(i);
      org.xipki.pkix.asn1.ocsp.CertID certId0 = singleReq0.getReqCert();
      ByteArrayOutputStream out = new ByteArrayOutputStream();

      try {
        out.write(certId0.getHashAlgorithm().getEncoded());
        out.write(certId0.getIssuerNameHash().getEncoded());
        out.write(certId0.getIssuerKeyHash().getEncoded());
        byte[] encodedIssuer = out.toByteArray();
        RequestIssuer issuer = new RequestIssuer(encodedIssuer,0, encodedIssuer.length);
        CertID certId = new CertID(issuer, certId0.serialNumber());
        requestList.add(certId);
      } catch (IOException | NoSuchAlgorithmException ex) {
        throw new EncodingException(ex.getMessage(), ex);
      }
    }

    List<ExtendedExtension> extensions = new LinkedList<>();
    if (extensions0 != null) {
      Set<Asn1Oid> extOids = extensions0.getExtensionIds();
      for (Asn1Oid oid : extOids) {
        Extension extension0 = extensions0.getExtension(oid);

        byte[] encoded = extension0.getEncoded();
        ExtendedExtension extn = ExtendedExtension.getInstance(encoded, 0, encoded.length);
        // null for unknown non-critical extension
        if (extn != null) {
          extensions.add(extn);
        }
      }
    }

    return new OcspRequest(tbsReq.version(), requestList, extensions);
  } // method getInstance

  public static int readRequestVersion(byte[] request) throws EncodingException {
    try {
      return readRequestVersion0(request);
    } catch (RuntimeException ex) {
      throw new EncodingException("malformed request: " + ex.getMessage(), ex);
    }
  }

  private static int readRequestVersion0(byte[] request) throws EncodingException {
    // OCSPRequest
    Header hdr = readHeader(request, 0);
    // tbsRequest
    hdr = readHeader(request, hdr.readerIndex);
    // First element of the tbsRequest
    hdr = readHeader(request, hdr.readerIndex);
    if ((hdr.tag & 0x1F) != 0) {
      // version not present, default to 0
      return 0;
    } else {
      hdr = readHeader(request, hdr.readerIndex);
      if (hdr.len == 1) {
        return 0xFF & request[hdr.readerIndex];
      } else {
        throw new EncodingException("version too large");
      }
    }
  } // method readRequestVersion

  public static boolean containsSignature(byte[] request) throws EncodingException {
    // OCSPRequest
    Header hdr = readHeader(request, 0);
    // tbsRequest
    Header hdrTbs = readHeader(request, hdr.readerIndex);
    return hdrTbs.end() < hdr.end();
  }

  static Header readHeader(byte[] encoded, int readerIndex) throws EncodingException {
    return readHeader(encoded, readerIndex, encoded.length);
  }

  static Header readHeader(byte[] encoded, int readerIndex, int limit, byte expectedTag)
      throws EncodingException {
    Header hdr = readHeader(encoded, readerIndex, limit);
    if (hdr.tag != expectedTag) {
      throw new EncodingException("unexpected tag at " + readerIndex);
    }
    return hdr;
  }

  static Header readHeader(byte[] encoded, int readerIndex, int limit)
      throws EncodingException {
    if (readerIndex < 0 || readerIndex + 2 > limit) {
      throw new EncodingException("truncated data at " + readerIndex);
    }

    int off = readerIndex;
    byte tag = encoded[off++];
    int len = 0xFF & encoded[off++];
    if (len >= 0x80) {
      int lenSize = len & 0x7F;
      if (off + lenSize > limit) {
        throw new EncodingException("truncated length field at " + readerIndex);
      }

      if (lenSize == 1) {
        len = 0xFF & encoded[off++];
      } else if (lenSize == 2) {
        len = ((0xFF & encoded[off++]) << 8)  | (0xFF & encoded[off++]);
      } else if (lenSize == 3) {
        len = ((0xFF & encoded[off++]) << 16) | ((0xFF & encoded[off++]) << 8)
            | (0xFF & encoded[off++]);
      } else if (lenSize == 4) {
        len = ((0xFF & encoded[off++]) << 24) | ((0xFF & encoded[off++]) << 16)
            | ((0xFF & encoded[off++]) << 8)  | (0xFF & encoded[off++]);
      } else {
        throw new EncodingException("invalid length field at " + readerIndex);
      }
    }

    // len < 0: 4-byte length field larger than Integer.MAX_VALUE
    if (len < 0 || len > limit - off) {
      throw new EncodingException("content exceeds the data at " + readerIndex);
    }
    return new Header(readerIndex, tag, len, off);
  } // method readHeader

  private static byte[] readContent(byte[] encoded, Header header) {
    byte[] content = new byte[header.len];
    System.arraycopy(encoded, header.readerIndex, content, 0, header.len);
    return content;
  }

  public int version() {
    return version;
  }

  public List<CertID> requestList() {
    return requestList;
  }

  public List<ExtendedExtension> extensions() {
    return extensions;
  }

}
