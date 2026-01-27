// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.junit.Test;
import org.xipki.util.codec.json.JsonInputStream;

import java.io.ByteArrayOutputStream;

/**
 * @author Lijun Liao (xipki)
 */
public class JsonReaderTest {

  @Test
  public void commentNotAllowedTest() throws Exception {
    String str = "{\r\n\"a\": \"v-a\", \n\"b\": \"v-b\"}";
    JsonInputStream reader = JsonInputStream.newReader(str, false);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    int r;
    while ((r = reader.read()) != -1) {
      bout.write(r);
    }

    System.out.write(bout.toByteArray());
    System.out.println();
  }

  @Test
  public void commentAllowedTest() throws Exception {
    String str = "{\r\n\"a\": \"v-a\", \n" +
        "  // comment 1\n" +
        "  // comment 2\n" +
        "\"b\": \"v-b\"}\n" +
        "  // comment 3\n" +
        "  // comment 4\n";

    JsonInputStream reader = JsonInputStream.newReader(str, true);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    int r;
    while ((r = reader.read()) != -1) {
      bout.write(r);
    }

    System.out.write(bout.toByteArray());
    System.out.println();
  }

}
