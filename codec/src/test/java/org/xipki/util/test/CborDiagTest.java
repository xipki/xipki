// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.junit.Test;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDiag;

import java.io.ByteArrayOutputStream;

/**
 * JUnit test case of printing the CBOR diagnostic notation.
 * @author Lijun Liao (xipki)
 */
public class CborDiagTest {

  @Test
  public void printDeeplyNestedArrays() throws CodecException {
    // deeply nested arrays shall be printed without exception, even if the
    // indent leaves no space for the comment.
    for (int depth = 1; depth <= 60; depth++) {
      byte[] encoded = new byte[depth + 1];
      for (int i = 0; i < depth; i++) {
        encoded[i] = (byte) 0x81; // array(1)
      }
      encoded[depth] = (byte) 0xF6; // null

      new CborDiag(encoded).print(new ByteArrayOutputStream());
    }
  }

}
