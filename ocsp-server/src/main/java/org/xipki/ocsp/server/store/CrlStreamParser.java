// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.AbstractAsn1Time;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Tags;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.asn1.util.ContentVerifier;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.asn1.Asn1StreamParser;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.misc.LogUtil;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Crl Stream Parser.
 *
 * Size of the consumed memory is linear to the size of CRL. This may cause
 * that OutOfMemory error for large CRLs.
 *
 * <p>This class implements a real stream based parser of CRL with constant
 * memory consumption.
 *
 * <p>Definition of CertificateList.
 *
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 *       tbsCertList          TBSCertList,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING  }
 *
 *  TBSCertList  ::=  SEQUENCE  {
 *       version                 Version OPTIONAL,
 *                                    -- if present, MUST be v2
 *       signature               AlgorithmIdentifier,
 *       issuer                  Name,
 *       thisUpdate              Time,
 *       nextUpdate              Time OPTIONAL,
 *       revokedCertificates     SEQUENCE OF SEQUENCE  {
 *            userCertificate         CertificateSerialNumber,
 *            revocationDate          Time,
 *            crlEntryExtensions      Extensions OPTIONAL
 *                                     -- if present, version MUST be v2
 *                                 }  OPTIONAL,
 *       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                     -- if present, version MUST be v2
 *                                 }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CrlStreamParser extends Asn1StreamParser {

  /**
   * Revoked certificate record.
   */
  public static class RevokedCert {

    private final BigInteger serialNumber;

    /**
     * EPOCH seconds of revocationDate.
     */
    private final long revocationDate;

    /**
     * CRLReason code.
     */
    private final CrlReason reason;

    /**
     * EPOCH seconds of revocationDate. Or 0 if not set.
     */
    private final long invalidityDate;

    private final X500Name certificateIssuer;

    private RevokedCert(
        BigInteger serialNumber, Instant revocationDate, CrlReason reason,
        Instant invalidityDate, X500Name certificateIssuer) {
      this.serialNumber = serialNumber;
      this.revocationDate = revocationDate.getEpochSecond();
      this.reason = reason;
      this.certificateIssuer = certificateIssuer;
      this.invalidityDate = (invalidityDate == null) ? 0
          : revocationDate.equals(invalidityDate) ? 0
          : invalidityDate.getEpochSecond();
    }

    public BigInteger serialNumber() {
      return serialNumber;
    }

    public long revocationDate() {
      return revocationDate;
    }

    public CrlReason reason() {
      return reason;
    }

    public long invalidityDate() {
      return invalidityDate;
    }

    public X500Name certificateIssuer() {
      return certificateIssuer;
    }

  } // class RevokedCert

  /**
   * Revoked Certs iterator.
   */
  public class RevokedCertsIterator implements Iterator<RevokedCert>, Closeable {

    private BufferedInputStream instream;

    private RevokedCert next;

    private int offset;

    // RFC 5280, Section 5.3.3: if the certificateIssuer extension is not present on an entry,
    // the certificate issuer defaults to that of the preceding entry, and to the CRL issuer
    // (null) for the first entry.
    private X500Name lastCertIssuer;

    private RevokedCertsIterator() throws IOException {
      this.instream = new BufferedInputStream(Files.newInputStream(crlFile.toPath()));
      skip(this.instream, firstRevokedCertificateOffset);
      this.offset = firstRevokedCertificateOffset;
      next0();
    }

    @Override
    public boolean hasNext() {
      return next != null;
    }

    @Override
    public RevokedCert next() {
      if (next == null) {
        throw new IllegalStateException("no next object anymore");
      }

      RevokedCert ret = next;
      next0();
      return ret;
    }

    private void next0() {
      if (offset >= revokedCertificatesEndIndex) {
        next = null;
        return;
      }

      byte[] bytes;
      try {
        bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "revokedCertificate");
      } catch (IOException ex) {
        throw new IllegalStateException("error reading next revokedCertificate", ex);
      }
      offset += bytes.length;

      /*
       * SEQUENCE  {
       *   userCertificate         CertificateSerialNumber,
       *   revocationDate          Time,
       *   crlEntryExtensions      Extensions OPTIONAL
       *                           -- if present, shall be v2
       * }
       */
      BigInteger serialNumber;
      Instant revocationDate;
      Instant invalidityDate = null;
      CrlReason reason = CrlReason.UNSPECIFIED;
      X500Name certIssuer = lastCertIssuer;

      try {
        Asn1Sequence revCert = Asn1Sequence.fromEncoded(bytes);
        serialNumber = revCert.getNonNegativeIntegerAt(0).getValue();
        revocationDate = readTime((AbstractAsn1Time) revCert.getObjectAt(1));

        if (revCert.size() > 2) {
          Extensions extns = Extensions.fromAsn1(revCert.getSequenceAt(2));
          Extension extn = extns.getExtension(ExtensionOIDs.certificateIssuer);
          if (extn != null) {
            certIssuer = extn.getCertificateIssuer().get(0).getDirectoryName();
          }

          extn = extns.getExtension(ExtensionOIDs.invalidityDate);
          if (extn != null) {
            invalidityDate = extn.invalidityDate();
          }

          extn = extns.getExtension(ExtensionOIDs.reasonCode);
          reason = extn == null ? CrlReason.UNSPECIFIED
              : CrlReason.forReasonCode(extn.getReasonCode().getValue());
        }
      } catch (CodecException e) {
        throw new IllegalStateException("error parsing CRLEntry", e);
      }

      lastCertIssuer = certIssuer;
      next = new RevokedCert(serialNumber, revocationDate, reason, invalidityDate, certIssuer);
    } // method next0

    @Override
    public void close() throws IOException {
      if (instream != null) {
        instream.close();
      }
      instream = null;
    }

  } // class RevokedCertsIterator

  private static final Logger LOG = LoggerFactory.getLogger(CrlStreamParser.class);

  private final File crlFile;

  private final int version;

  private final X500Name issuer;

  private final Instant thisUpdate;

  private final Instant nextUpdate;

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] signature;

  private final BigInteger crlNumber;

  private final BigInteger baseCrlNumber;

  private final Extensions crlExtensions;

  private final int firstRevokedCertificateOffset;

  // end index (exclusive) of revokedCertificates
  private final int revokedCertificatesEndIndex;

  private final int tbsCertListOffset;

  // end index (exclusive) of tbsCertList
  private final int tbsCertListEndIndex;

  public CrlStreamParser(File crlFile) throws IOException, CodecException {
    this.crlFile = Args.notNull(crlFile, "crlFile");
    // Round 1
    try (BufferedInputStream instream = new BufferedInputStream(
        Files.newInputStream(crlFile.toPath()))) {
      int offset = 0;
      // Tag SEQUENCE of CertificateList
      int tag = markAndReadTag(instream);
      if (tag == '-') {
        throw new IllegalArgumentException("The CRL is not DER encoded.");
      }
      assertTag(TAG_CONSTRUCTED_SEQUENCE, tag, "CertificateList");

      offset++;

      MyInt lenBytesSize = new MyInt();

      // Length SEQUENCE of CertificateList
      readLength(lenBytesSize, instream);
      offset += lenBytesSize.get();

      // tbsCertList
      tbsCertListOffset = offset;
      tag = markAndReadTag(instream);
      assertTag(TAG_CONSTRUCTED_SEQUENCE, tag, "tbsCertList");
      offset++;

      int tbsCertListLength = readLength(lenBytesSize, instream);
      offset += lenBytesSize.get();
      tbsCertListEndIndex = offset + tbsCertListLength;

      // parse the tbsCert except revokedCertificates
      byte[] bytes;

      //       version                 Version OPTIONAL,
      //                                    -- if present, MUST be v2
      tag = peekTag(instream);
      instream.reset();

      if (tag == Asn1Tags.INTEGER) {
        // optional field version is available
        bytes = readBlock(instream, "tbsCertList.version");
        offset += bytes.length;

        this.version = Asn1Integer.fromEncodedNonNegative(bytes).intValueExact();
      } else {
        this.version = 0; // default version v1
      }

      //       signature               AlgorithmIdentifier,
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "tbsCertList.signature");
      offset += bytes.length;

      AlgorithmIdentifier tbsSignature = AlgorithmIdentifier.fromEncoded(bytes);

      //       issuer                  Name,
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "tbsCertList.issuer");
      offset += bytes.length;
      this.issuer = X500Name.fromEncoded(bytes);

      //       thisUpdate              Time,
      MyInt bytesLen = new MyInt();
      this.thisUpdate = readTime(bytesLen, instream, "tbsCertList.thisUpdate");
      offset += bytesLen.get();

      //       nextUpdate              Time OPTIONAL,
      // the next field may be also the revokedCertificates (SEQUENCE) or
      // crlExtensions ([0]), or be outside the tbsCertList.
      tag = peekTag(instream);
      if (offset < tbsCertListEndIndex
          && (tag == Asn1Tags.UTC_TIME || tag == Asn1Tags.GENERALIZED_TIME)) {
        this.nextUpdate = readTime(bytesLen, instream, "tbsCertList.nextUpdate");
        offset += bytesLen.get();
        tag = peekTag(instream);
      } else {
        this.nextUpdate = null;
      }

      // revokedCertificates     SEQUENCE OF SEQUENCE  { ... } OPTIONAL
      if (offset < tbsCertListEndIndex && TAG_CONSTRUCTED_SEQUENCE == tag) {
        markAndReadTag(instream);
        offset++;
        int revokedCertificatesLength = readLength(lenBytesSize, instream);
        offset += lenBytesSize.get();

        this.firstRevokedCertificateOffset = offset;
        this.revokedCertificatesEndIndex = offset + revokedCertificatesLength;

        // skip the revokedCertificates
        skip(instream, revokedCertificatesLength);
        offset += revokedCertificatesLength;
      } else {
        this.revokedCertificatesEndIndex = -1;
        this.firstRevokedCertificateOffset = -1;
      }

      // [0] EXPLICIT
      int crlExtensionsTag = Asn1Tags.CONTEXT_SPECIFIC | Asn1Tags.CONSTRUCTED;

      Extensions extns = null;
      if (offset < tbsCertListEndIndex) {
        while (offset < tbsCertListEndIndex) {
          tag = markAndReadTag(instream);

          offset++;

          int length = readLength(bytesLen, instream);
          offset += bytesLen.get();

          if (tag != crlExtensionsTag) {
            skip(instream, length);
            offset += length;
          } else {
            instream.mark(1);
            // crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
            bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "crlExtensions");
            offset += bytes.length;
            extns = Extensions.fromEncoded(bytes);
          }
        }
      }

      this.crlExtensions = extns;

      if (this.crlExtensions != null) {
        Extension extn = this.crlExtensions.getExtension(ExtensionOIDs.cRLNumber);
        this.crlNumber = (extn == null) ? null : extn.cRLNumber();

        extn = this.crlExtensions.getExtension(ExtensionOIDs.deltaCRLIndicator);
        this.baseCrlNumber = (extn == null) ? null : extn.deltaCRLIndicator();
      } else {
        this.crlNumber = null;
        this.baseCrlNumber = null;
      }

      // From now on, the offset will not be needed anymore, so do not update
      // it.
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "signatureAlgorithm");
      this.algorithmIdentifier = AlgorithmIdentifier.fromEncoded(bytes);
      if (!tbsSignature.equals(this.algorithmIdentifier)) {
        throw new IllegalArgumentException("algorithmIdentifier != tbsCertList.signature");
      }

      bytes = readBlock(Asn1Tags.BIT_STRING, instream, "signature");
      this.signature = Asn1BitString.fromEncoded(bytes).getAlignedOctets();
    }
  } // constructor

  public int version() {
    return version;
  }

  public X500Name issuer() {
    return issuer;
  }

  public Instant thisUpdate() {
    return thisUpdate;
  }

  public Instant nextUpdate() {
    return nextUpdate;
  }

  public AlgorithmIdentifier algorithmIdentifier() {
    return algorithmIdentifier;
  }

  public byte[] signature() {
    return Arrays.copyOf(signature, signature.length);
  }

  public BigInteger crlNumber() {
    return crlNumber;
  }

  public BigInteger baseCrlNumber() {
    return baseCrlNumber;
  }

  public boolean isDeltaCrl() {
    return baseCrlNumber != null;
  }

  public Extensions crlExtensions() {
    return crlExtensions;
  }

  public boolean verifySignature(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
    PublicKey publicKey;
    try {
      publicKey = KeyInfoUtil.getPublicKey(publicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new IllegalArgumentException("error parsing public key", ex);
    }
    return verifySignature(publicKey);
  }

  public boolean verifySignature(PublicKey publicKey) throws IOException {
    try {
      ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(publicKey);
      ContentVerifier verifier = cvp.get(algorithmIdentifier);
      OutputStream sigOut = verifier.getOutputStream();
      try (InputStream crlStream = Files.newInputStream(crlFile.toPath())) {
        skip(crlStream, tbsCertListOffset);

        int remainingLength = tbsCertListEndIndex - tbsCertListOffset;
        byte[] buffer = new byte[1024];

        while (true) {
          int count = crlStream.read(buffer);
          if (count == -1) {
            break;
          } else if (count > 0) {
            if (count <= remainingLength) {
              sigOut.write(buffer, 0, count);
              remainingLength -= count;
            } else {
              sigOut.write(buffer, 0, remainingLength);
              remainingLength = 0;
            }
          }

          if (remainingLength == 0) {
            break;
          }
        }

        if (remainingLength != 0) {
          throw new IOException("could reading all tbsCertList");
        }
      }

      sigOut.close();

      return verifier.verify(this.signature());
    } catch (InvalidKeyException | GenerationException | SignatureException ex) {
      LogUtil.error(LOG, ex, "could not validate POP of CSR");
      return false;
    }
  } // method verifySignature

  public RevokedCertsIterator revokedCertificates() throws IOException {
    return new RevokedCertsIterator();
  }
}
