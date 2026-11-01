// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * JUnit tests of {@link DnsMessage}, {@link WireReader} and {@link DnsName}.
 *
 * @author Lijun Liao (xipki)
 */
public class DnsMessageTest {

  private static void assertMalformed(byte[] msg, String expectedText) {
    try {
      DnsMessage.parse(msg);
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains(expectedText));
    }
  }

  @Test
  public void buildQuery() throws Exception {
    byte[] q = DnsMessage.buildQuery(0x1234, DnsName.of("Example.ORG"),
        DnsRecord.TYPE_TXT, true, true);
    byte[] expected = new TestWire().header(0x1234,
            DnsMessage.FLAG_RD | DnsMessage.FLAG_CD, 0, 1, 0, 0, 1)
        .question("example.org", DnsRecord.TYPE_TXT)
        .opt(DnsMessage.EDNS_UDP_SIZE, 0, true, new byte[0]).toByteArray();
    Assert.assertArrayEquals(expected, q);

    q = DnsMessage.buildQuery(1, DnsName.of("example.org"), DnsRecord.TYPE_TXT, false, false);
    expected = new TestWire().header(1, DnsMessage.FLAG_RD, 0, 1, 0, 0, 0)
        .question("example.org", DnsRecord.TYPE_TXT).toByteArray();
    Assert.assertArrayEquals(expected, q);
  }

  @Test
  public void parseWithCompression() throws Exception {
    TestWire w = new TestWire().header(7, DnsMessage.FLAG_QR | DnsMessage.FLAG_AD, 0,
        1, 3, 0, 0);
    int qnameOffset = w.size();
    w.question("_acme-challenge.EXAMPLE.org", DnsRecord.TYPE_TXT);

    // CNAME, owner and target compressed
    byte[] cnameRdata = new TestWire().u8(3).bytes("WWW".getBytes(StandardCharsets.US_ASCII))
        .pointer(qnameOffset + 16).toByteArray();
    w.pointer(qnameOffset).u16(DnsRecord.TYPE_CNAME).u16(1).u32(60)
        .u16(cnameRdata.length).bytes(cnameRdata);

    // TXT with two strings
    w.pointer(qnameOffset).u16(DnsRecord.TYPE_TXT).u16(1).u32(60).u16(8)
        .u8(3).bytes("abc".getBytes()).u8(3).bytes("def".getBytes());

    // RRSIG with compressed signer name: stored uncompressed
    byte[] fixed = new byte[18];
    fixed[1] = DnsRecord.TYPE_TXT;
    w.pointer(qnameOffset).u16(DnsRecord.TYPE_RRSIG).u16(1).u32(60).u16(18 + 2 + 4)
        .bytes(fixed).pointer(qnameOffset + 16).bytes(new byte[]{1, 2, 3, 4});

    DnsMessage m = DnsMessage.parse(w.toByteArray());
    Assert.assertEquals(7, m.id());
    Assert.assertTrue(m.flag(DnsMessage.FLAG_AD));
    Assert.assertFalse(m.flag(DnsMessage.FLAG_TC));
    Assert.assertEquals(DnsName.of("_acme-challenge.example.org"), m.qname());
    Assert.assertEquals(3, m.answer().size());

    DnsRecord cname = m.answer().get(0);
    Assert.assertEquals(m.qname(), cname.name());
    Assert.assertEquals(DnsName.of("www.example.org"), cname.cnameTarget());
    Assert.assertArrayEquals(DnsName.of("www.example.org").toWire(), cname.rdata());

    Assert.assertEquals("abcdef", m.answer().get(1).txt());

    DnsRecord rrsig = m.answer().get(2);
    Assert.assertEquals(DnsRecord.TYPE_TXT, rrsig.typeCovered());
    byte[] signer = DnsName.of("example.org").toWire();
    Assert.assertEquals(18 + signer.length + 4, rrsig.rdata().length);
  }

  @Test
  public void parseEde() throws Exception {
    byte[] text = "signature expired".getBytes(StandardCharsets.UTF_8);
    byte[] options = new TestWire().u16(10).u16(2).u16(0) // other option, skipped
        .u16(15).u16(2 + text.length).u16(7).bytes(text).toByteArray();
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, DnsMessage.RCODE_SERVFAIL,
            1, 0, 0, 1).question("example.org", DnsRecord.TYPE_TXT)
        .opt(1232, 0, true, options).toByteArray();
    DnsMessage m = DnsMessage.parse(msg);
    Assert.assertEquals(DnsMessage.RCODE_SERVFAIL, m.rcode());
    Assert.assertEquals(7, m.edeCode());
    Assert.assertEquals("signature expired", m.edeText());
    Assert.assertTrue(m.additional().isEmpty());
  }

  @Test
  public void extendedRcode() throws Exception {
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 1, 0, 0, 1)
        .question("example.org", DnsRecord.TYPE_TXT).opt(1232, 1, false, new byte[0])
        .toByteArray();
    Assert.assertEquals(16, DnsMessage.parse(msg).rcode()); // BADVERS
  }

  @Test
  public void forwardPointer() {
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 1, 0, 0, 0)
        .pointer(14).u8(0).u16(16).u16(1).toByteArray();
    assertMalformed(msg, "does not point backwards");
  }

  @Test
  public void pointerToItself() {
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 1, 0, 0, 0)
        .pointer(12).u16(16).u16(1).toByteArray();
    assertMalformed(msg, "does not point backwards");
  }

  @Test
  public void pointerLoop() {
    // name at 12: label "a" then pointer to 12 -> loop; the pointer at 14 points back to 12
    TestWire w = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 1, 0, 0, 0)
        .u8(1).u8('a').pointer(12).u16(16).u16(1);
    byte[] msg = w.toByteArray();
    try {
      DnsMessage.parse(msg);
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      String m = ex.getMessage();
      Assert.assertTrue(m, m.contains("too many compression pointers")
          || m.contains("does not point backwards") || m.contains("too long"));
    }
  }

  @Test
  public void truncatedMessages() throws Exception {
    byte[] msg = TestWire.txtResponse(DnsMessage.buildQuery(1, DnsName.of("example.org"),
        DnsRecord.TYPE_TXT, false, false), 0, "token");
    DnsMessage.parse(msg);
    for (int len = 0; len < msg.length; len++) {
      byte[] truncated = new byte[len];
      System.arraycopy(msg, 0, truncated, 0, len);
      try {
        DnsMessage.parse(truncated);
        Assert.fail("truncated message of length " + len + " accepted");
      } catch (DnsException ex) {
        // expected
      }
    }
  }

  @Test
  public void trailingData() throws Exception {
    byte[] msg = TestWire.txtResponse(DnsMessage.buildQuery(1, DnsName.of("example.org"),
        DnsRecord.TYPE_TXT, false, false), 0, "token");
    byte[] longer = new byte[msg.length + 1];
    System.arraycopy(msg, 0, longer, 0, msg.length);
    assertMalformed(longer, "trailing data");
  }

  @Test
  public void rdataLengthMismatch() {
    // CNAME whose name ends before RDLENGTH
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 0, 1, 0, 0)
        .name("a.org").u16(DnsRecord.TYPE_CNAME).u16(1).u32(60).u16(8).name("b.org").u8(0)
        .toByteArray();
    assertMalformed(msg, "RDATA length mismatch");
  }

  @Test
  public void otherOpcodeRejected() {
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR | (5 << 11), 0, 0, 0, 0, 0)
        .toByteArray();
    assertMalformed(msg, "opcode");
  }

  @Test
  public void optOutsideAdditional() {
    byte[] msg = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 0, 1, 0, 0)
        .opt(1232, 0, false, new byte[0]).toByteArray();
    assertMalformed(msg, "misplaced OPT");
  }

  @Test
  public void nameTooLong() {
    TestWire w = new TestWire().header(1, DnsMessage.FLAG_QR, 0, 1, 0, 0, 0);
    for (int i = 0; i < 5; i++) {
      w.u8(63).bytes(new byte[63]);
    }
    w.u8(0).u16(16).u16(1);
    assertMalformed(w.toByteArray(), "too long");
  }

  @Test
  public void dnsName() {
    DnsName name = DnsName.of("_Acme-Challenge.Example.ORG.");
    Assert.assertEquals("_acme-challenge.example.org.", name.toString());
    Assert.assertEquals(3, name.labelCount());
    Assert.assertEquals(DnsName.of("example.org"), name.parent());
    Assert.assertTrue(name.isSubdomainOf(DnsName.of("ORG")));
    Assert.assertTrue(name.isSubdomainOf(name));
    Assert.assertFalse(name.isProperSubdomainOf(name));
    Assert.assertTrue(name.isProperSubdomainOf(DnsName.ROOT));
    Assert.assertFalse(name.isSubdomainOf(DnsName.of("ample.org")));
    Assert.assertEquals(DnsName.ROOT, DnsName.of("."));

    for (String invalid : new String[]{"", "a..b", "a b.org", "ä.org", "*.example.org",
        "a\\.b"}) {
      try {
        DnsName.of(invalid);
        Assert.fail("accepted invalid name '" + invalid + "'");
      } catch (IllegalArgumentException ex) {
        // expected
      }
    }
  }

}
