// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * DNS message (RFC 1035 section 4) with EDNS(0) (RFC 6891). Only what a stub resolver
 * needs: building a query with one question and parsing a response.
 *
 * @author Lijun Liao (xipki)
 */
public final class DnsMessage {

  public static final int FLAG_QR = 0x8000;

  public static final int FLAG_TC = 0x0200;

  public static final int FLAG_RD = 0x0100;

  public static final int FLAG_AD = 0x0020;

  public static final int FLAG_CD = 0x0010;

  public static final int RCODE_NOERROR = 0;

  public static final int RCODE_FORMERR = 1;

  public static final int RCODE_SERVFAIL = 2;

  public static final int RCODE_NXDOMAIN = 3;

  public static final int RCODE_NOTIMP = 4;

  public static final int RCODE_REFUSED = 5;

  /** UDP payload size recommended by DNS flag day 2020. */
  public static final int EDNS_UDP_SIZE = 1232;

  private static final int EDNS_FLAG_DO = 0x8000;

  private static final int EDNS_OPTION_EDE = 15;

  private final int id;

  private final int flags;

  private final int rcode;

  private final DnsName qname;

  private final int qtype;

  private final int qclass;

  private final List<DnsRecord> answer;

  private final List<DnsRecord> authority;

  private final List<DnsRecord> additional;

  private int edeCode = -1;

  private String edeText;

  /**
   * Constructor.
   *
   * @param id the message ID.
   * @param flags the flags of the header (without opcode and rcode).
   * @param rcode the (extended) response code.
   * @param qname the name in the question, may be {@code null}.
   * @param qtype the type in the question.
   * @param answer the answer section.
   * @param authority the authority section, without the OPT record.
   * @param additional the additional section, without the OPT record.
   */
  public DnsMessage(int id, int flags, int rcode, DnsName qname, int qtype,
                    List<DnsRecord> answer, List<DnsRecord> authority,
                    List<DnsRecord> additional) {
    this(id, flags, rcode, qname, qtype, DnsRecord.CLASS_IN, answer, authority, additional);
  }

  private DnsMessage(int id, int flags, int rcode, DnsName qname, int qtype, int qclass,
                     List<DnsRecord> answer, List<DnsRecord> authority,
                     List<DnsRecord> additional) {
    this.id = id;
    this.flags = flags;
    this.rcode = rcode;
    this.qname = qname;
    this.qtype = qtype;
    this.qclass = qclass;
    this.answer = Collections.unmodifiableList(answer);
    this.authority = Collections.unmodifiableList(authority);
    this.additional = Collections.unmodifiableList(additional);
  }

  public int id() {
    return id;
  }

  public boolean flag(int flag) {
    return (flags & flag) != 0;
  }

  public int rcode() {
    return rcode;
  }

  public DnsName qname() {
    return qname;
  }

  public int qtype() {
    return qtype;
  }

  public int qclass() {
    return qclass;
  }

  public List<DnsRecord> answer() {
    return answer;
  }

  public List<DnsRecord> authority() {
    return authority;
  }

  public List<DnsRecord> additional() {
    return additional;
  }

  /**
   * Returns the records of the answer section with the given owner and type. The other
   * records, and the authority and additional sections, are ignored.
   */
  public List<DnsRecord> answer(DnsName owner, int type) {
    List<DnsRecord> ret = new ArrayList<>(2);
    for (DnsRecord rr : answer) {
      if (rr.type() == type && rr.name().equals(owner)) {
        ret.add(rr);
      }
    }
    return ret;
  }

  /**
   * Returns the RRSIG records of the answer section with the given owner that cover the
   * given type.
   */
  public List<DnsRecord> rrsigs(DnsName owner, int typeCovered) {
    List<DnsRecord> ret = new ArrayList<>(2);
    for (DnsRecord rr : answer) {
      if (rr.type() == DnsRecord.TYPE_RRSIG && rr.name().equals(owner)
          && rr.typeCovered() == typeCovered) {
        ret.add(rr);
      }
    }
    return ret;
  }

  /**
   * Returns the INFO-CODE of the Extended DNS Error (RFC 8914), or -1 if absent.
   */
  public int edeCode() {
    return edeCode;
  }

  /**
   * Returns the EXTRA-TEXT of the Extended DNS Error (RFC 8914), or {@code null}.
   */
  public String edeText() {
    return edeText;
  }

  public static String rcodeText(int rcode) {
    switch (rcode) {
      case RCODE_NOERROR:
        return "NOERROR";
      case RCODE_FORMERR:
        return "FORMERR";
      case RCODE_SERVFAIL:
        return "SERVFAIL";
      case RCODE_NXDOMAIN:
        return "NXDOMAIN";
      case RCODE_NOTIMP:
        return "NOTIMP";
      case RCODE_REFUSED:
        return "REFUSED";
      default:
        return "RCODE" + rcode;
    }
  }

  /**
   * Builds a query with one question of class IN and RD=1.
   *
   * @param id the message ID.
   * @param qname the name to query.
   * @param qtype the type to query.
   * @param edns whether to add an OPT record.
   * @param dnssec whether to set DO=1 (requires edns) and CD=1. With CD=1 the resolver
   *        returns the DNSSEC records unvalidated, so that the caller can validate them.
   * @return the encoded query.
   */
  public static byte[] buildQuery(int id, DnsName qname, int qtype, boolean edns,
                                  boolean dnssec) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(64);
    int flags = FLAG_RD | (dnssec ? FLAG_CD : 0);
    write16(out, id);
    write16(out, flags);
    write16(out, 1); // QDCOUNT
    write16(out, 0); // ANCOUNT
    write16(out, 0); // NSCOUNT
    write16(out, edns ? 1 : 0); // ARCOUNT

    qname.writeTo(out);
    write16(out, qtype);
    write16(out, DnsRecord.CLASS_IN);

    if (edns) {
      out.write(0); // root name
      write16(out, DnsRecord.TYPE_OPT);
      write16(out, EDNS_UDP_SIZE);
      // TTL: extended rcode 0, version 0, flags
      write16(out, 0);
      write16(out, dnssec ? EDNS_FLAG_DO : 0);
      write16(out, 0); // RDLENGTH
    }
    return out.toByteArray();
  }

  /**
   * Writes the 16-bit value in network byte order.
   */
  public static void write16(ByteArrayOutputStream out, int v) {
    out.write(v >>> 8);
    out.write(v);
  }

  /**
   * Parses a message.
   *
   * @param msg the encoded message.
   * @return the parsed message.
   * @throws DnsException if the message is malformed.
   */
  public static DnsMessage parse(byte[] msg) throws DnsException {
    WireReader r = new WireReader(msg);
    int id = r.u16();
    int flagsAndCodes = r.u16();
    int qdcount = r.u16();
    int ancount = r.u16();
    int nscount = r.u16();
    int arcount = r.u16();

    int opcode = (flagsAndCodes >>> 11) & 0xF;
    if (opcode != 0) {
      throw new DnsException("unexpected opcode " + opcode);
    }

    if (qdcount > 1) {
      throw new DnsException("more than one question");
    }

    DnsName qname = null;
    int qtype = 0;
    int qclass = 0;
    if (qdcount == 1) {
      qname = r.name(msg);
      qtype = r.u16();
      qclass = r.u16();
    }

    List<DnsRecord> answer = readSection(r, msg, ancount, null);
    List<DnsRecord> authority = readSection(r, msg, nscount, null);
    List<DnsRecord> opts = new ArrayList<>(1);
    List<DnsRecord> additional = readSection(r, msg, arcount, opts);

    if (r.remaining() != 0) {
      throw new DnsException("trailing data after DNS message");
    }

    if (opts.size() > 1) {
      throw new DnsException("more than one OPT record");
    }

    int rcode = flagsAndCodes & 0xF;
    int flags = flagsAndCodes & 0x87F0;
    DnsRecord opt = opts.isEmpty() ? null : opts.get(0);
    if (opt != null) {
      rcode |= (int) ((opt.ttl() >>> 24) << 4);
    }

    DnsMessage ret = new DnsMessage(id, flags, rcode, qname, qtype, qclass,
        answer, authority, additional);
    if (opt != null) {
      ret.parseOptions(opt.rdata());
    }
    return ret;
  }

  private void parseOptions(byte[] rdata) throws DnsException {
    WireReader r = new WireReader(rdata);
    while (r.remaining() > 0) {
      int code = r.u16();
      int len = r.u16();
      if (code == EDNS_OPTION_EDE && len >= 2 && edeCode == -1) {
        edeCode = r.u16();
        edeText = new String(r.bytes(len - 2), StandardCharsets.UTF_8);
      } else {
        r.skip(len);
      }
    }
  }

  private static List<DnsRecord> readSection(WireReader r, byte[] msg, int count,
                                             List<DnsRecord> opts) throws DnsException {
    List<DnsRecord> records = new ArrayList<>(Math.min(count, 64));
    for (int i = 0; i < count; i++) {
      DnsName name = r.name(msg);
      int type = r.u16();
      int dclass = r.u16();
      long ttl = r.u32();
      int rdlength = r.u16();
      if (rdlength > r.remaining()) {
        throw new DnsException("truncated RDATA");
      }

      int rdataEnd = r.position() + rdlength;
      byte[] rdata;
      if (type == DnsRecord.TYPE_CNAME) {
        rdata = r.name(msg).toWire();
      } else if (type == DnsRecord.TYPE_RRSIG) {
        // 18 octets fixed fields, signer's name, signature
        byte[] fixed = r.bytes(18);
        byte[] signer = r.name(msg).toWire();
        byte[] signature = r.bytes(rdataEnd - r.position());
        rdata = new byte[fixed.length + signer.length + signature.length];
        System.arraycopy(fixed, 0, rdata, 0, fixed.length);
        System.arraycopy(signer, 0, rdata, fixed.length, signer.length);
        System.arraycopy(signature, 0, rdata, fixed.length + signer.length, signature.length);
      } else {
        rdata = r.bytes(rdlength);
      }

      if (r.position() != rdataEnd) {
        throw new DnsException("RDATA length mismatch for type " + type);
      }

      DnsRecord record = new DnsRecord(name, type, dclass, ttl, rdata);
      if (type == DnsRecord.TYPE_OPT) {
        if (opts == null || !name.isRoot()) {
          throw new DnsException("misplaced OPT record");
        }
        opts.add(record);
      } else {
        records.add(record);
      }
    }
    return records;
  }

}
