/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security;

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
import java.text.ParseException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

/**
 * Both BouncyCastle and JDK read the whole CRL during the initialization. The
 * size of the consumed memory is linear to the size of CRL. This may cause
 * that OutOfMemory error for large CRLs.
 * <p/>
 * This class implements a real stream based parser of CRL with constant memory
 * consumption.
 * <p/>
 * Definition of CertificateList.
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
public class CrlStreamParser {

  public static class RevokedCert {

    private BigInteger serialNumber;

    private Date revocationDate;

    private CrlReason reason;

    private Date invalidityDate;

    private X500Name certificateIssuer;

    private RevokedCert(BigInteger serialNumber, Date revocationDate, CrlReason reason,
        Date invalidityDate, X500Name certificateIssuer) {
      this.serialNumber = serialNumber;
      this.revocationDate = revocationDate;
      this.reason = reason == null ? CrlReason.UNSPECIFIED : reason;
      this.invalidityDate = invalidityDate;
      this.certificateIssuer = certificateIssuer;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public Date getRevocationDate() {
      return revocationDate;
    }

    public CrlReason getReason() {
      return reason;
    }

    public Date getInvalidityDate() {
      return invalidityDate;
    }

    public X500Name getCertificateIssuer() {
      return certificateIssuer;
    }

  }

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
      Date revocationDate = Time.getInstance(revCert.getObjectAt(1)).getDate();
      Date invalidityDate = null;
      CrlReason reason = null;
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
          invalidityDate = Time.getInstance(coreExtValue).getDate();
        }

        coreExtValue = X509Util.getCoreExtValue(extns, Extension.reasonCode);
        CRLReason bcReason = CRLReason.getInstance(coreExtValue);
        reason = CrlReason.forReasonCode(bcReason.getValue().intValue());
      }

      next = new RevokedCert(serialNumber, revocationDate, reason, invalidityDate,
                  certificateIssuer);
    }

    @Override
    public void close() throws IOException {
      if (instream != null) {
        instream.close();
      }
      instream = null;
    }

  }

  private static class MyInt {

    private int value;

    void set(int value) {
      this.value = value;
    }

    int get() {
      return value;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(CrlStreamParser.class);

  private static final int TAG_CONSTRUCTED_SEQUENCE = BERTags.CONSTRUCTED | BERTags.SEQUENCE;

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

      //       revokedCertificates     SEQUENCE OF SEQUENCE  { ... }
      assertTag(TAG_CONSTRUCTED_SEQUENCE, tag, "tbsCertList.revokedCertificates");
      int revokedCertificatesOffset = offset;
      int revokedCertificatesLength = readLength(lenBytesSize, instream);
      offset += lenBytesSize.get();

      this.revokedCertificatesEndIndex = revokedCertificatesOffset + revokedCertificatesLength;
      this.firstRevokedCertificateOffset = offset;

      // skip the revokedCertificates
      skip(instream, revokedCertificatesLength);
      offset += revokedCertificatesLength;

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
  }

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
  }

  public RevokedCertsIterator revokedCertificates() throws IOException {
    return new RevokedCertsIterator();
  }

  private static byte[] readBlock(int expectedTag, BufferedInputStream instream, String name)
      throws IOException {
    instream.mark(10);
    int tag = instream.read();
    assertTag(expectedTag, tag, name);

    return readBlock(instream, name);
  }

  private static byte[] readBlock(BufferedInputStream instream, String name)
      throws IOException {
    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream);
    instream.reset();

    byte[] bytes = new byte[1 + lenBytesSize.get() + length];
    if (bytes.length != instream.read(bytes)) {
      throw new IOException("error reading " + name);
    }
    return bytes;
  }

  private static int markAndReadTag(InputStream instream) throws IOException {
    instream.mark(10);
    return instream.read();
  }

  private static int readLength(MyInt lenBytesSize, InputStream instream) throws IOException {
    // Length SEQUENCE of CertificateList
    int b = instream.read();
    if ((b & 0x80) == 0) {
      lenBytesSize.set(1);
      return b;
    } else {
      byte[] lengthBytes = new byte[b & 0x7F];
      if (lengthBytes.length > 4) {
        throw new IOException("length too long");
      }
      lenBytesSize.set(1 + lengthBytes.length);

      instream.read(lengthBytes);

      int length = 0xFF & lengthBytes[0];
      for (int i = 1; i < lengthBytes.length; i++) {
        length = (length << 8) + (0xFF & lengthBytes[i]);
      }
      return length;
    }
  }

  private static void assertTag(int expectedTag, int tag, String name) {
    if (expectedTag != tag) {
      throw new IllegalArgumentException(
          String.format("invalid %s: tag is %d, but not expected %d", name, tag, expectedTag));
    }
  }

  private static Date readTime(MyInt bytesLen, BufferedInputStream instream, String name)
      throws IOException {
    int tag = markAndReadTag(instream);
    byte[] bytes = readBlock(instream, name);
    bytesLen.set(bytes.length);
    try {
      if (tag == BERTags.UTC_TIME) {
        return DERUTCTime.getInstance(bytes).getDate();
      } else if (tag == BERTags.GENERALIZED_TIME) {
        return DERGeneralizedTime.getInstance(bytes).getDate();
      } else {
        throw new IllegalArgumentException("invalid tag for " + name + ": " + tag);
      }
    } catch (ParseException ex) {
      throw new IllegalArgumentException("error parsing time", ex);
    }
  }

  private static void skip(InputStream instream, long count) throws IOException {
    long remaining = count;
    while (remaining > 0) {
      remaining -= instream.skip(remaining);
    }
  }
}
