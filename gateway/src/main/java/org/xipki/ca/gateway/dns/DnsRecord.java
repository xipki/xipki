// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Resource record. The RDATA is stored in canonical form (RFC 4034 section 6.2):
 * names in the RDATA of CNAME and RRSIG are uncompressed and in lower case.
 *
 * @author Lijun Liao (xipki)
 */
public final class DnsRecord {

  public static final int TYPE_A = 1;

  public static final int TYPE_CNAME = 5;

  public static final int TYPE_TXT = 16;

  public static final int TYPE_AAAA = 28;

  public static final int TYPE_DNAME = 39;

  public static final int TYPE_OPT = 41;

  public static final int TYPE_DS = 43;

  public static final int TYPE_RRSIG = 46;

  public static final int TYPE_DNSKEY = 48;

  public static final int CLASS_IN = 1;

  private final DnsName name;

  private final int type;

  private final int dclass;

  private final long ttl;

  private final byte[] rdata;

  public DnsRecord(DnsName name, int type, int dclass, long ttl, byte[] rdata) {
    this.name = Objects.requireNonNull(name, "name");
    this.type = type;
    this.dclass = dclass;
    this.ttl = ttl;
    this.rdata = Objects.requireNonNull(rdata, "rdata");
  }

  public DnsName name() {
    return name;
  }

  public int type() {
    return type;
  }

  public int dclass() {
    return dclass;
  }

  public long ttl() {
    return ttl;
  }

  public byte[] rdata() {
    return rdata;
  }

  /**
   * Returns the type covered by this RRSIG record, or -1 if it is not an RRSIG record.
   */
  public int typeCovered() {
    if (type != TYPE_RRSIG || rdata.length < 2) {
      return -1;
    }
    return ((rdata[0] & 0xFF) << 8) | (rdata[1] & 0xFF);
  }

  /**
   * Returns the concatenation of all character-strings of this TXT record
   * (RFC 7208 section 3.3), decoded as ISO-8859-1.
   *
   * @throws DnsException if this is not a valid TXT record.
   */
  public String txt() throws DnsException {
    if (type != TYPE_TXT) {
      throw new DnsException("not a TXT record");
    }

    StringBuilder sb = new StringBuilder();
    WireReader r = new WireReader(rdata);
    while (r.remaining() > 0) {
      int len = r.u8();
      sb.append(new String(r.bytes(len), StandardCharsets.ISO_8859_1));
    }
    return sb.toString();
  }

  /**
   * Returns the target of this CNAME record.
   *
   * @throws DnsException if this is not a valid CNAME record.
   */
  public DnsName cnameTarget() throws DnsException {
    if (type != TYPE_CNAME) {
      throw new DnsException("not a CNAME record");
    }

    WireReader r = new WireReader(rdata);
    DnsName target = r.name();
    if (r.remaining() != 0) {
      throw new DnsException("invalid CNAME RDATA");
    }
    return target;
  }

  @Override
  public String toString() {
    return name + " " + ttl + " class " + dclass + " type " + type;
  }

}
