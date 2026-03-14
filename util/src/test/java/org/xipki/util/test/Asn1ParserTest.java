// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.misc.Asn1Parser;

import java.util.List;

/**
 * Test for {@link Asn1Parser}.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1ParserTest {

  @Test
  public void testParseInteger() {
    byte[] encoded = new byte[]{0x02, 0x01, 0x05};
    List<Asn1Parser.Asn1Object> objects = Asn1Parser.parse(encoded);

    Assert.assertEquals(1, objects.size());
    Asn1Parser.Asn1Object obj = objects.get(0);
    Assert.assertEquals(Asn1Parser.TagClass.UNIVERSAL, obj.tagClass());
    Assert.assertFalse(obj.constructed());
    Assert.assertEquals(2, obj.tagNumber());
    Assert.assertEquals(1, obj.valueLength());
    Assert.assertArrayEquals(new byte[]{0x05}, obj.value());
    Assert.assertTrue(obj.children().isEmpty());
  }

  @Test
  public void testParseSequence() {
    byte[] encoded = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x7F};

    List<Asn1Parser.Asn1Object> objects = Asn1Parser.parse(encoded);
    Assert.assertEquals(1, objects.size());

    Asn1Parser.Asn1Object seq = objects.get(0);
    Assert.assertTrue(seq.constructed());
    Assert.assertEquals(2, seq.children().size());
    Assert.assertEquals(2, seq.children().get(0).tagNumber()); // INTEGER
    Assert.assertEquals(4, seq.children().get(1).tagNumber()); // OCTET STRING
  }

  @Test
  public void testParseHighTagNumber() {
    // [APPLICATION 31] primitive, length 1, value 0x00
    byte[] encoded = new byte[]{0x5F, 0x1F, 0x01, 0x00};
    List<Asn1Parser.Asn1Object> objects = Asn1Parser.parse(encoded);

    Assert.assertEquals(1, objects.size());
    Asn1Parser.Asn1Object obj = objects.get(0);
    Assert.assertEquals(Asn1Parser.TagClass.APPLICATION, obj.tagClass());
    Assert.assertEquals(31, obj.tagNumber());
    Assert.assertFalse(obj.constructed());
    Assert.assertArrayEquals(new byte[]{0x00}, obj.value());
  }

  @Test
  public void testParseIndefiniteLengthConstructed() {
    // SEQUENCE (indefinite): INTEGER 1, EOC
    byte[] encoded = new byte[]{0x30, (byte) 0x80, 0x02, 0x01, 0x01, 0x00, 0x00};

    List<Asn1Parser.Asn1Object> objects = Asn1Parser.parse(encoded);
    Assert.assertEquals(1, objects.size());

    Asn1Parser.Asn1Object seq = objects.get(0);
    Assert.assertTrue(seq.constructed());
    Assert.assertEquals(1, seq.children().size());
    Assert.assertEquals(2, seq.children().get(0).tagNumber());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testRejectOverflowLength() {
    // OCTET STRING length 5, but only 1 content byte present
    Asn1Parser.parse(new byte[]{0x04, 0x05, 0x00});
  }

  @Test(expected = IllegalArgumentException.class)
  public void testRejectIndefinitePrimitive() {
    // Primitive INTEGER with indefinite length must be rejected
    Asn1Parser.parse(new byte[]{0x02, (byte) 0x80, 0x00, 0x00});
  }
}
