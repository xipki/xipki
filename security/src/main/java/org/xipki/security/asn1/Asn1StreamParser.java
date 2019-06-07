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
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.xipki.security.util.X509Util;

/**
 * ASN.1 stream parser.
 *
 * @author Lijun Liao
 *
 */
public class Asn1StreamParser {

  protected static class MyInt {

    private int value;

    void set(int value) {
      this.value = value;
    }

    int get() {
      return value;
    }

  } // class MyInt

  protected static final int TAG_CONSTRUCTED_SEQUENCE = BERTags.CONSTRUCTED | BERTags.SEQUENCE;

  protected static byte[] readBlock(int expectedTag, BufferedInputStream instream, String name)
      throws IOException {
    instream.mark(10);
    int tag = instream.read();
    assertTag(expectedTag, tag, name);

    return readBlock(instream, name);
  }

  protected static byte[] readBlock(BufferedInputStream instream, String name)
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

  protected static int markAndReadTag(InputStream instream) throws IOException {
    instream.mark(10);
    return instream.read();
  }

  protected static int readLength(MyInt lenBytesSize, InputStream instream) throws IOException {
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

  protected static void assertTag(int expectedTag, int tag, String name) {
    if (expectedTag != tag) {
      throw new IllegalArgumentException(
          String.format("invalid %s: tag is %d, but not expected %d", name, tag, expectedTag));
    }
  }

  protected static Date readTime(Object obj) {
    return X509Util.getTime(obj);
  }

  protected static Date readTime(MyInt bytesLen, BufferedInputStream instream, String name)
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

  protected static void skip(InputStream instream, long count) throws IOException {
    long remaining = count;
    while (remaining > 0) {
      remaining -= instream.skip(remaining);
    }
  }

}
