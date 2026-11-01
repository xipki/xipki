// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.io.ByteArrayOutputStream;

/**
 * Writer of raw DNS messages for tests.
 *
 * @author Lijun Liao (xipki)
 */
final class TestWire {

  private final ByteArrayOutputStream out = new ByteArrayOutputStream();

  /** Writes the header. */
  TestWire header(int id, int flags, int rcode, int qd, int an, int ns, int ar) {
    return u16(id).u16(flags | (rcode & 0xF)).u16(qd).u16(an).u16(ns).u16(ar);
  }

  TestWire question(String name, int type) {
    return name(name).u16(type).u16(DnsRecord.CLASS_IN);
  }

  /** Writes a record with uncompressed owner name. */
  TestWire record(String name, int type, long ttl, byte[] rdata) {
    return name(name).u16(type).u16(DnsRecord.CLASS_IN).u32(ttl).u16(rdata.length).bytes(rdata);
  }

  TestWire opt(int udpSize, int extRcode, boolean dnssecOk, byte[] options) {
    return u8(0).u16(DnsRecord.TYPE_OPT).u16(udpSize).u8(extRcode).u8(0)
        .u16(dnssecOk ? 0x8000 : 0).u16(options.length).bytes(options);
  }

  TestWire name(String name) {
    byte[] wire = DnsName.of(name).toWire();
    return bytes(wire);
  }

  TestWire pointer(int offset) {
    return u8(0xC0 | (offset >>> 8)).u8(offset);
  }

  TestWire u8(int v) {
    out.write(v);
    return this;
  }

  TestWire u16(int v) {
    out.write(v >>> 8);
    out.write(v);
    return this;
  }

  TestWire u32(long v) {
    return u16((int) (v >>> 16)).u16((int) v);
  }

  TestWire bytes(byte[] b) {
    out.write(b, 0, b.length);
    return this;
  }

  int size() {
    return out.size();
  }

  byte[] toByteArray() {
    return out.toByteArray();
  }

  /**
   * Returns a NOERROR response to the query with the given TXT strings.
   */
  static byte[] txtResponse(byte[] query, int flags, String... txts) throws DnsException {
    DnsMessage q = DnsMessage.parse(query);
    TestWire w = new TestWire().header(q.id(), DnsMessage.FLAG_QR | flags, 0, 1, txts.length,
        0, 0).question(q.qname().toString(), q.qtype());
    for (String txt : txts) {
      byte[] b = txt.getBytes();
      byte[] rdata = new byte[1 + b.length];
      rdata[0] = (byte) b.length;
      System.arraycopy(b, 0, rdata, 1, b.length);
      w.record(q.qname().toString(), DnsRecord.TYPE_TXT, 60, rdata);
    }
    return w.toByteArray();
  }

}
