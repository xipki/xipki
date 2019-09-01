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

package org.xipki.security.asn1;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.util.Args;

/**
 * This class implements a real stream based parser of XiPKI CrlCertSet with
 * constant memory consumption.
 *
 * <p>Definition of Xipki-CrlCertSet.
 *
 * <pre>
 * Xipki-CrlCertSet ::= SET OF Xipki-CrlCert
 *
 * Xipki-CrlCert ::= SEQUENCE {
 *   serial          INTEGER,
 *   cert        [0] EXPLICIT    Certificate OPTIONAL,
 *   info        [1] EXPLICIT    UTF8String  OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao
 *
 */
public class CrlCertSetStreamParser extends Asn1StreamParser {

  public static class CrlCert {

    private BigInteger serial;

    private Certificate cert;

    private CrlCert(BigInteger serial, Certificate cert) {
      this.serial = serial;
      this.cert = cert;
    }

    public BigInteger getSerial() {
      return serial;
    }

    public void setSerial(BigInteger serial) {
      this.serial = serial;
    }

    public Certificate getCert() {
      return cert;
    }

    public void setCert(Certificate cert) {
      this.cert = cert;
    }

  } // class CrlCert

  public class CrlCertsIterator implements Iterator<CrlCert>, Closeable {

    private CrlCert next;

    private CrlCertsIterator() throws IOException {
      next0();
    }

    @Override
    public boolean hasNext() {
      return next != null;
    }

    @Override
    public CrlCert next() {
      if (next == null) {
        throw new IllegalStateException("no next object anymore");
      }

      CrlCert ret = next;
      next0();
      return ret;
    }

    private void next0() {
      if (offset >= endIndex) {
        next = null;
        return;
      }

      byte[] bytes;
      try {
        bytes = readBlock(TAG_CONSTRUCTED_SEQUENCE, instream, "crlCert");
      } catch (IOException ex) {
        throw new IllegalStateException("error reading next crlCert", ex);
      }
      offset += bytes.length;

      /*
       * Xipki-CrlCert ::= SEQUENCE {
       *   serial          INTEGER
       *   cert        [0] EXPLICIT    Certificate OPTIONAL
       * }
       */
      ASN1Sequence seq = ASN1Sequence.getInstance(bytes);
      BigInteger serialNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();

      Certificate cert = null;

      final int size = seq.size();
      for (int j = 1; j < size; j++) {
        ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(seq.getObjectAt(j));
        int tagNo = taggedObj.getTagNo();
        switch (tagNo) {
          case 0:
            cert = Certificate.getInstance(taggedObj.getObject());
            break;
          default:
            break;
        }
      }

      next = new CrlCert(serialNumber, cert);
    } // method next0

    @Override
    public void close() throws IOException {
      if (instream != null) {
        instream.close();
      }
      instream = null;
    }

  } // class CrlCertsIterator

  private BufferedInputStream instream;

  private int endIndex;

  private int offset;

  public CrlCertSetStreamParser(InputStream instream) throws IOException {
    Args.notNull(instream, "instream");
    if (instream instanceof BufferedInputStream) {
      this.instream = (BufferedInputStream) instream;
    } else {
      this.instream = new BufferedInputStream(instream);
    }
    int tag = markAndReadTag(instream);
    assertTag(TAG_CONSTRUCTED_SET, tag, "Xipki-CrlCertSet");
    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream);
    offset = 1 + lenBytesSize.get();
    endIndex = offset + length;
  }

  public CrlCertsIterator crlCerts() throws IOException {
    return new CrlCertsIterator();
  }
}
