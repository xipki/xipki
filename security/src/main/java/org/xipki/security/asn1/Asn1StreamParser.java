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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x509.Time;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;

/**
 * ASN.1 stream parser.
 *
 * @author Lijun Liao
 *
 */
public class Asn1StreamParser {

  public static class MyInt {

    private int value;

    void set(int value) {
      this.value = value;
    }

    public int get() {
      return value;
    }

  } // class MyInt

  public static final int TAG_CONSTRUCTED_SEQUENCE = BERTags.CONSTRUCTED | BERTags.SEQUENCE;

  public static final int TAG_CONSTRUCTED_SET = BERTags.CONSTRUCTED | BERTags.SET;

  public static byte[] readBlock(int expectedTag, BufferedInputStream instream, String name)
      throws IOException {
    instream.mark(10);
    int tag = instream.read();
    assertTag(expectedTag, tag, name);

    return readBlock(instream, name);
  }

  public static byte[] readBlock(BufferedInputStream instream, String name)
      throws IOException {
    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream);
    instream.reset();

    byte[] bytes = new byte[1 + lenBytesSize.get() + length];
    if (bytes.length != instream.read(bytes)) {
      throw new IOException("error reading " + name);
    }
    return bytes;
  } // method readBlock

  public static byte[] readValue(int expectedTag, BufferedInputStream instream, String name)
          throws IOException {
    instream.mark(10);
    int tag = instream.read();
    assertTag(expectedTag, tag, name);

    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream);

    byte[] bytes = new byte[length];
    if (bytes.length != instream.read(bytes)) {
      throw new IOException("error reading " + name);
    }
    return bytes;
  } // method readValue

  public static int markAndReadTag(InputStream instream)
      throws IOException {
    instream.mark(10);
    return instream.read();
  }

  public static int readLength(MyInt lenBytesSize, InputStream instream)
      throws IOException {
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
  } // method readLength

  public static void assertTag(int expectedTag, int tag, String name) {
    if (expectedTag != tag) {
      throw new IllegalArgumentException(
          String.format("invalid %s: tag is %d, but not expected %d", name, tag, expectedTag));
    }
  }

  public static Date readTime(ASN1Encodable  obj) {
    if (obj instanceof Time) {
      return ((Time) obj).getDate();
    } else if (obj instanceof org.bouncycastle.asn1.cms.Time) {
      return ((org.bouncycastle.asn1.cms.Time) obj).getDate();
    } else {
      return Time.getInstance(obj).getDate();
    }
  }

  public static Date readTime(MyInt bytesLen, BufferedInputStream instream, String name)
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
  } // method readTime

  public static void skip(InputStream instream, long count)
      throws IOException {
    long remaining = count;
    while (remaining > 0) {
      remaining -= instream.skip(remaining);
    }
  }

}
