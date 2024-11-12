// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.CrlReason;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

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
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Iterator;

/**
 * Both BouncyCastle and JDK read the whole CRL during the initialization. The
 * size of the consumed memory is linear to the size of CRL. This may cause
 * that OutOfMemory error for large CRLs.
 *
 * <p>This class implements a real stream based parser of CRL with constant memory
 * consumption.
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
 *
 */
public class CrlStreamParser extends Asn1StreamParser {

  public static class RevokedCert {

    private final BigInteger serialNumber;

    /**
     * EPOCH seconds of revocationDate.
     */
    private final long revocationDate;

    /**
     * CRLReason code.
     */
    private final int reason;

    /**
     * EPOCH seconds of revocationDate. Or 0 if not set.
     */
    private final long invalidityDate;

    private final X500Name certificateIssuer;

    private RevokedCert(
        BigInteger serialNumber, Instant revocationDate, int reason, Instant invalidityDate,
        X500Name certificateIssuer) {
      this.serialNumber = serialNumber;
      this.revocationDate = revocationDate.getEpochSecond();
      this.reason = reason;
      this.certificateIssuer = certificateIssuer;
      this.invalidityDate = (invalidityDate == null) ? 0
          : revocationDate.equals(invalidityDate) ? 0
          : invalidityDate.getEpochSecond();
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public long getRevocationDate() {
      return revocationDate;
    }

    public int getReason() {
      return reason;
    }

    public long getInvalidityDate() {
      return invalidityDate;
    }

    public X500Name getCertificateIssuer() {
      return certificateIssuer;
    }

  } // class RevokedCert

  public class RevokedCertsIterator implements Iterator<RevokedCert>, Closeable {

    private BufferedInputStream instream;

    private RevokedCert next;

    private int offset;

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
      ASN1Sequence revCert = ASN1Sequence.getInstance(bytes);
      BigInteger serialNumber = ASN1Integer.getInstance(revCert.getObjectAt(0)).getValue();
      Instant revocationDate = readTime(revCert.getObjectAt(1));
      Instant invalidityDate = null;
      int reason = 0;
      X500Name certificateIssuer = null;

      if (revCert.size() > 2) {
        Extensions extns = Extensions.getInstance(revCert.getObjectAt(2));
        byte[] coreExtValue = X509Util.getCoreExtValue(extns, Extension.certificateIssuer);
        if (coreExtValue != null) {
          certificateIssuer = X500Name.getInstance(GeneralNames.getInstance(coreExtValue).getNames()[0].getName());
        }

        coreExtValue = X509Util.getCoreExtValue(extns, Extension.invalidityDate);
        if (coreExtValue != null) {
          int tag = coreExtValue[0] & 0xFF;
          try {
            if (tag == BERTags.UTC_TIME) {
              invalidityDate = DERUTCTime.getInstance(coreExtValue).getDate().toInstant();
            } else if (tag == BERTags.GENERALIZED_TIME) {
              invalidityDate = DERGeneralizedTime.getInstance(coreExtValue).getDate().toInstant();
            } else {
              throw new IllegalArgumentException("invalid tag " + tag);
            }
          } catch (ParseException ex) {
            throw new IllegalArgumentException("error parsing time", ex);
          }
        }

        coreExtValue = X509Util.getCoreExtValue(extns, Extension.reasonCode);
        reason = coreExtValue == null ? CrlReason.UNSPECIFIED.getCode()
            : CRLReason.getInstance(coreExtValue).getValue().intValue();
      }

      next = new RevokedCert(serialNumber, revocationDate, reason, invalidityDate, certificateIssuer);
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

  public CrlStreamParser(File crlFile) throws IOException {
    this.crlFile = Args.notNull(crlFile, "crlFile");
    // Round 1
    try (BufferedInputStream instream = new BufferedInputStream(Files.newInputStream(crlFile.toPath()))) {
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

      if (tag == BERTags.INTEGER) {
        // optional field version is available
        bytes = readBlock(instream, "tbsCertList.version");
        offset += bytes.length;

        this.version = ASN1Integer.getInstance(bytes).getValue().intValue();
      } else {
        this.version = 0; // default version v1
      }

      //       signature               AlgorithmIdentifier,
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "tbsCertList.signature");
      offset += bytes.length;

      AlgorithmIdentifier tbsSignature = AlgorithmIdentifier.getInstance(bytes);

      //       issuer                  Name,
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "tbsCertList.issuer");
      offset += bytes.length;
      this.issuer = X500Name.getInstance(bytes);

      //       thisUpdate              Time,
      MyInt bytesLen = new MyInt();
      this.thisUpdate = readTime(bytesLen, instream, "tbsCertList.thisUpdate");
      offset += bytesLen.get();

      //       nextUpdate              Time OPTIONAL,
      tag = peekTag(instream);
      if (tag != TAG_CONSTRUCTED_SEQUENCE) {
        instream.reset();
        this.nextUpdate = readTime(bytesLen, instream, "tbsCertList.thisUpdate");
        offset += bytesLen.get();
        tag = peekTag(instream);
      } else {
        this.nextUpdate = null;
      }

      offset++;

      //       revokedCertificates     SEQUENCE OF SEQUENCE  { ... } OPTIONAL
      if (offset < tbsCertListLength && TAG_CONSTRUCTED_SEQUENCE == tag) {
        markAndReadTag(instream);
        int revokedCertificatesOffset = offset;
        int revokedCertificatesLength = readLength(lenBytesSize, instream);
        offset += lenBytesSize.get();

        this.revokedCertificatesEndIndex = revokedCertificatesOffset + revokedCertificatesLength;
        this.firstRevokedCertificateOffset = offset;

        // skip the revokedCertificates
        skip(instream, revokedCertificatesLength);
        offset += revokedCertificatesLength;
      } else {
        this.revokedCertificatesEndIndex = -1;
        this.firstRevokedCertificateOffset = -1;
      }

      int crlExtensionsTag = BERTags.TAGGED | BERTags.CONSTRUCTED; // [0] EXPLICIT

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
            //       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
            bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "crlExtensions");
            offset += bytes.length;
            extns = Extensions.getInstance(bytes);
          }
        }
      }

      this.crlExtensions = extns;

      if (this.crlExtensions != null) {
        bytes = X509Util.getCoreExtValue(this.crlExtensions, Extension.cRLNumber);
        this.crlNumber = (bytes == null) ? null : ASN1Integer.getInstance(bytes).getValue();

        bytes = X509Util.getCoreExtValue(this.crlExtensions, Extension.deltaCRLIndicator);
        this.baseCrlNumber = (bytes == null) ? null : ASN1Integer.getInstance(bytes).getPositiveValue();
      } else {
        this.crlNumber = null;
        this.baseCrlNumber = null;
      }

      // From now on, the offset will not be needed anymore, so do not update it.
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "signatureAlgorithm");
      this.algorithmIdentifier = AlgorithmIdentifier.getInstance(bytes);
      if (!tbsSignature.equals(this.algorithmIdentifier)) {
        throw new IllegalArgumentException("algorithmIdentifier != tbsCertList.signature");
      }

      bytes = readBlock(BERTags.BIT_STRING, instream, "signature");
      this.signature = ASN1BitString.getInstance(bytes).getBytes();
    }
  } // constructor

  public int getVersion() {
    return version;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public Instant getThisUpdate() {
    return thisUpdate;
  }

  public Instant getNextUpdate() {
    return nextUpdate;
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  public byte[] getSignature() {
    return Arrays.copyOf(signature, signature.length);
  }

  public BigInteger getCrlNumber() {
    return crlNumber;
  }

  public BigInteger getBaseCrlNumber() {
    return baseCrlNumber;
  }

  public boolean isDeltaCrl() {
    return baseCrlNumber != null;
  }

  public Extensions getCrlExtensions() {
    return crlExtensions;
  }

  public boolean verifySignature(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
    PublicKey publicKey;
    try {
      publicKey = KeyUtil.generatePublicKey(publicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new IllegalArgumentException("error parsing public key", ex);
    }
    return verifySignature(publicKey);
  }

  public boolean verifySignature(PublicKey publicKey) throws IOException {
    try {
      ContentVerifierProvider cvp = SignerUtil.getContentVerifierProvider(publicKey, null);
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

      return verifier.verify(this.getSignature());
    } catch (InvalidKeyException | OperatorCreationException ex) {
      LogUtil.error(LOG, ex, "could not validate POP of CSR");
      return false;
    }
  } // method verifySignature

  public RevokedCertsIterator revokedCertificates() throws IOException {
    return new RevokedCertsIterator();
  }
}
