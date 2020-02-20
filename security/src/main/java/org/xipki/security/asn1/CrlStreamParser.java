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

package org.xipki.security.asn1;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
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
 * @author Lijun Liao
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

    private RevokedCert(BigInteger serialNumber, Date revocationDate, int reason,
        Date invalidityDate, X500Name certificateIssuer) {
      this.serialNumber = serialNumber;
      this.revocationDate = revocationDate.getTime() / 1000;
      this.reason = reason;
      if (invalidityDate == null) {
        this.invalidityDate = 0;
      } else {
        this.invalidityDate =
            revocationDate.equals(invalidityDate) ? 0 : invalidityDate.getTime() / 1000;
      }

      this.certificateIssuer = certificateIssuer;
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
      this.instream = new BufferedInputStream(new FileInputStream(crlFile));
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
      Date revocationDate = readTime(revCert.getObjectAt(1));
      Date invalidityDate = null;
      int reason = 0;
      X500Name certificateIssuer = null;

      if (revCert.size() > 2) {
        Extensions extns = Extensions.getInstance(revCert.getObjectAt(2));
        byte[] coreExtValue = X509Util.getCoreExtValue(extns, Extension.certificateIssuer);
        if (coreExtValue != null) {
          certificateIssuer = X500Name.getInstance(
                                GeneralNames.getInstance(coreExtValue).getNames()[0].getName());
        }

        coreExtValue = X509Util.getCoreExtValue(extns, Extension.invalidityDate);
        if (coreExtValue != null) {
          invalidityDate = readTime(coreExtValue);
        }

        coreExtValue = X509Util.getCoreExtValue(extns, Extension.reasonCode);
        if (coreExtValue == null) {
          reason = CrlReason.UNSPECIFIED.getCode();
        } else {
          reason = CRLReason.getInstance(coreExtValue).getValue().intValue();
        }
      }

      next = new RevokedCert(serialNumber, revocationDate, reason, invalidityDate,
                  certificateIssuer);
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

  private final Date thisUpdate;

  private final Date nextUpdate;

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
    try (BufferedInputStream instream = new BufferedInputStream(
        new FileInputStream(crlFile))) {
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

      // CHECKSTYLE:SKIP
      int tbsCertListLength = readLength(lenBytesSize, instream);
      offset += lenBytesSize.get();
      // CHECKSTYLE:SKIP
      tbsCertListEndIndex = offset + tbsCertListLength;

      // parse the tbsCert except revokedCertificates
      byte[] bytes;

      //       version                 Version OPTIONAL,
      //                                    -- if present, MUST be v2
      tag = markAndReadTag(instream);

      if (tag == BERTags.INTEGER) {
        // optional field version is available
        bytes = readBlock(instream, "tbsCertList.version");
        offset += bytes.length;

        this.version = ASN1Integer.getInstance(bytes).getValue().intValue();
        tag = markAndReadTag(instream);
      } else {
        this.version = 0; // default version v1
      }

      //       signature               AlgorithmIdentifier,
      assertTag(TAG_CONSTRUCTED_SEQUENCE, tag, "tbsCertList.signature");
      bytes = readBlock(instream, "tbsCertList.signature");
      offset += bytes.length;

      // CHECKSTYLE:SKIP
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
      tag = markAndReadTag(instream);
      if (tag != TAG_CONSTRUCTED_SEQUENCE) {
        instream.reset();
        this.nextUpdate = readTime(bytesLen, instream, "tbsCertList.thisUpdate");
        offset += bytesLen.get();
        tag = markAndReadTag(instream);
      } else {
        this.nextUpdate = null;
      }

      offset++;

      //       revokedCertificates     SEQUENCE OF SEQUENCE  { ... } OPTIONAL
      if (TAG_CONSTRUCTED_SEQUENCE == tag) {
        int revokedCertificatesOffset = offset;
        int revokedCertificatesLength = readLength(lenBytesSize, instream);
        offset += lenBytesSize.get();

        this.revokedCertificatesEndIndex = revokedCertificatesOffset + revokedCertificatesLength;
        this.firstRevokedCertificateOffset = offset;

        // skip the revokedCertificates
        skip(instream, revokedCertificatesLength);
        offset += revokedCertificatesLength;
        tag = -1;
      } else {
        instream.reset();
        this.revokedCertificatesEndIndex = offset;
        this.firstRevokedCertificateOffset = offset;
      }

      int crlExtensionsTag = BERTags.TAGGED | BERTags.CONSTRUCTED | 0; // [0] EXPLICIT

      Extensions extns = null;
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

      this.crlExtensions = extns;

      if (this.crlExtensions != null) {
        bytes = X509Util.getCoreExtValue(this.crlExtensions, Extension.cRLNumber);
        this.crlNumber = ASN1Integer.getInstance(bytes).getValue();

        bytes = X509Util.getCoreExtValue(this.crlExtensions, Extension.deltaCRLIndicator);
        if (bytes == null) {
          this.baseCrlNumber = null;
        } else {
          this.baseCrlNumber = ASN1Integer.getInstance(bytes).getPositiveValue();
        }
      } else {
        this.crlNumber = null;
        this.baseCrlNumber = null;
      }

      // From now on, the offset will not be needed anymore, so do update it.
      bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "signatureAlgorithm");
      this.algorithmIdentifier = AlgorithmIdentifier.getInstance(bytes);
      if (!tbsSignature.equals(this.algorithmIdentifier)) {
        throw new IllegalArgumentException("algorithmIdentifier != tbsCertList.signature");
      }

      bytes = readBlock(BERTags.BIT_STRING, instream, "signature");
      this.signature = DERBitString.getInstance(bytes).getBytes();
    }
  } // constructor

  public int getVersion() {
    return version;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public Date getThisUpdate() {
    return thisUpdate;
  }

  public Date getNextUpdate() {
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
      try (InputStream crlStream = new FileInputStream(crlFile)) {
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
      LogUtil.error(LOG, ex, "could not validate POPO of CSR");
      return false;
    }
  } // method verifySignature

  public RevokedCertsIterator revokedCertificates() throws IOException {
    return new RevokedCertsIterator();
  }
}
