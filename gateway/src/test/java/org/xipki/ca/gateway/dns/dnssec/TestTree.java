// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.xipki.ca.gateway.dns.DnsException;
import org.xipki.ca.gateway.dns.DnsMessage;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.ca.gateway.dns.DnsTransport;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Synthetic signed zone tree, served by an in-memory {@link DnsTransport}.
 * Each zone has a KSK, which signs the DNSKEY RRset and is referenced by the DS in the
 * parent zone, and a ZSK, which signs the other RRsets of the zone.
 *
 * @author Lijun Liao (xipki)
 */
final class TestTree implements DnsTransport {

  static final long NOW = 1_800_000_000L;

  static final long TTL = 3600;

  // key pairs are expensive to generate (RSA): reuse them across tests
  private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<>();

  static final class MutableClock extends Clock {

    long millis = NOW * 1000;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public long millis() {
      return millis;
    }

    @Override
    public Instant instant() {
      return Instant.ofEpochMilli(millis);
    }

  }

  static final class Zone {

    final DnsName name;
    final TestKey ksk;
    final TestKey zsk;
    final List<TestKey> extraKeys = new ArrayList<>();
    int dsDigestType = 2;

    Zone(DnsName name, TestKey ksk, TestKey zsk) {
      this.name = name;
      this.ksk = ksk;
      this.zsk = zsk;
    }

  }

  /** Builder of an RRSIG record, with all fields modifiable. */
  final class Sig {

    DnsName owner;
    int typeCovered;
    List<DnsRecord> rrset;
    TestKey key;
    int algorithm;
    int labels;
    long originalTtl = TTL;
    long expiration = NOW + 86400;
    long inception = NOW - 3600;
    int keyTag;
    DnsName signer;
    int dclass = DnsRecord.CLASS_IN;

    Sig(DnsName owner, int type, List<DnsRecord> rrset, TestKey key, DnsName signer) {
      this.owner = owner;
      this.typeCovered = type;
      this.rrset = rrset;
      this.key = key;
      this.algorithm = key.algorithm;
      this.labels = owner.labelCount();
      this.keyTag = key.keyTag();
      this.signer = signer;
    }

    DnsRecord build() throws GeneralSecurityException {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      write16(out, typeCovered);
      out.write(algorithm);
      out.write(labels);
      write32(out, originalTtl);
      write32(out, expiration);
      write32(out, inception);
      write16(out, keyTag);
      byte[] signerWire = signer.toWire();
      out.write(signerWire, 0, signerWire.length);

      byte[] signedPart = out.toByteArray();
      DnssecValidator.Rrsig sig;
      try {
        sig = new DnssecValidator.Rrsig(signedPart);
      } catch (DnsException ex) {
        throw new IllegalStateException(ex);
      }

      byte[] data = DnssecValidator.signedData(owner, typeCovered, rrset, sig);
      byte[] signature = key.sign(data);
      out.write(signature, 0, signature.length);
      return new DnsRecord(owner, DnsRecord.TYPE_RRSIG, dclass, TTL, out.toByteArray());
    }

  }

  final MutableClock clock = new MutableClock();

  final Map<DnsName, Zone> zones = new LinkedHashMap<>();

  private final Map<String, List<DnsRecord>> answers = new HashMap<>();

  private final Map<String, List<DnsRecord>> additionals = new HashMap<>();

  private final Map<String, Integer> rcodes = new HashMap<>();

  private final List<Object[]> data = new ArrayList<>();

  int queryCount;

  // key pairs of trees with different ids are different
  private final String id;

  TestTree() {
    this("");
  }

  TestTree(String id) {
    this.id = id;
  }

  /**
   * Adds a zone. The parent zone must be added before.
   */
  Zone addZone(String name, int algorithm) throws GeneralSecurityException {
    DnsName zoneName = DnsName.of(name);
    Zone zone = new Zone(zoneName,
        new TestKey(algorithm, TestKey.FLAGS_KSK, keyPair(id + name + "/ksk", algorithm)),
        new TestKey(algorithm, TestKey.FLAGS_ZSK, keyPair(id + name + "/zsk", algorithm)));
    zones.put(zoneName, zone);
    return zone;
  }

  private static synchronized KeyPair keyPair(String id, int algorithm)
      throws GeneralSecurityException {
    String key = id + "/" + algorithm;
    KeyPair kp = KEY_PAIRS.get(key);
    if (kp == null) {
      kp = TestKey.generate(algorithm);
      KEY_PAIRS.put(key, kp);
    }
    return kp;
  }

  Zone zone(String name) {
    return zones.get(DnsName.of(name));
  }

  /**
   * Adds an RRset, signed by the ZSK of the zone in {@link #build()}.
   */
  void addData(String zone, String owner, int type, byte[]... rdatas) {
    data.add(new Object[]{DnsName.of(zone), DnsName.of(owner), type, rdatas});
  }

  /**
   * (Re-)creates and signs all RRsets.
   */
  TestTree build() throws GeneralSecurityException {
    answers.clear();
    for (Zone zone : zones.values()) {
      List<DnsRecord> keys = new ArrayList<>();
      keys.add(rr(zone.name, DnsRecord.TYPE_DNSKEY, zone.ksk.dnskeyRdata()));
      keys.add(rr(zone.name, DnsRecord.TYPE_DNSKEY, zone.zsk.dnskeyRdata()));
      for (TestKey extra : zone.extraKeys) {
        keys.add(rr(zone.name, DnsRecord.TYPE_DNSKEY, extra.dnskeyRdata()));
      }
      put(zone.name, DnsRecord.TYPE_DNSKEY, keys,
          sig(zone.name, DnsRecord.TYPE_DNSKEY, keys, zone.ksk, zone.name).build());

      if (!zone.name.isRoot()) {
        Zone parent = parentZone(zone.name);
        List<DnsRecord> ds = Collections.singletonList(dsRecord(zone, zone.ksk));
        put(zone.name, DnsRecord.TYPE_DS, ds,
            sig(zone.name, DnsRecord.TYPE_DS, ds, parent.zsk, parent.name).build());
      }
    }

    for (Object[] entry : data) {
      Zone zone = zones.get((DnsName) entry[0]);
      DnsName owner = (DnsName) entry[1];
      int type = (Integer) entry[2];
      List<DnsRecord> rrset = new ArrayList<>();
      for (byte[] rdata : (byte[][]) entry[3]) {
        rrset.add(rr(owner, type, rdata));
      }
      put(owner, type, rrset, sig(owner, type, rrset, zone.zsk, zone.name).build());
    }
    return this;
  }

  Zone parentZone(DnsName name) {
    DnsName p = name;
    while (!p.isRoot()) {
      p = p.parent();
      Zone zone = zones.get(p);
      if (zone != null) {
        return zone;
      }
    }
    throw new IllegalStateException("no parent zone of " + name);
  }

  DnsRecord dsRecord(Zone zone, TestKey key) {
    byte[] digest = zone.dsDigestType == 1
        ? new byte[20] : DnssecCrypto.dsDigest(zone.dsDigestType, zone.name, key.dnskeyRdata());
    byte[] rdata = new byte[4 + digest.length];
    rdata[0] = (byte) (key.keyTag() >>> 8);
    rdata[1] = (byte) key.keyTag();
    rdata[2] = (byte) key.algorithm;
    rdata[3] = (byte) zone.dsDigestType;
    System.arraycopy(digest, 0, rdata, 4, digest.length);
    return rr(zone.name, DnsRecord.TYPE_DS, rdata);
  }

  Sig sig(DnsName owner, int type, List<DnsRecord> rrset, TestKey key, DnsName signer) {
    return new Sig(owner, type, rrset, key, signer);
  }

  /** Replaces the answer of the query (owner, type). */
  void put(DnsName owner, int type, List<DnsRecord> rrset, DnsRecord... rrsigs) {
    List<DnsRecord> answer = new ArrayList<>(rrset);
    answer.addAll(Arrays.asList(rrsigs));
    answers.put(key(owner, type), answer);
  }

  List<DnsRecord> answer(DnsName owner, int type) {
    List<DnsRecord> answer = answers.get(key(owner, type));
    return answer == null ? new ArrayList<>() : new ArrayList<>(answer);
  }

  void putAdditional(DnsName owner, int type, List<DnsRecord> records) {
    additionals.put(key(owner, type), records);
  }

  void setRcode(DnsName owner, int type, int rcode) {
    rcodes.put(key(owner, type), rcode);
  }

  /** Returns the DS of the root KSK. */
  List<DnsRecord> trustAnchors() {
    Zone root = zones.get(DnsName.ROOT);
    return Collections.singletonList(dsRecord(root, root.ksk));
  }

  DnssecValidator validator() {
    return new DnssecValidator(this, trustAnchors(), clock);
  }

  @Override
  public DnsMessage query(DnsName qname, int qtype) {
    queryCount++;
    String key = key(qname, qtype);
    Integer rcode = rcodes.get(key);
    List<DnsRecord> answer = answers.get(key);
    if (answer == null && qtype != DnsRecord.TYPE_CNAME) {
      // as a resolver: the CNAME of the name answers queries of other types
      answer = answers.get(key(qname, DnsRecord.TYPE_CNAME));
    }
    List<DnsRecord> additional = additionals.get(key);
    return new DnsMessage(0, DnsMessage.FLAG_QR,
        rcode == null ? DnsMessage.RCODE_NOERROR : rcode, qname, qtype,
        answer == null ? Collections.emptyList() : answer, Collections.emptyList(),
        additional == null ? Collections.emptyList() : additional);
  }

  private static String key(DnsName owner, int type) {
    return owner + "/" + type;
  }

  static DnsRecord rr(DnsName owner, int type, byte[] rdata) {
    return new DnsRecord(owner, type, DnsRecord.CLASS_IN, TTL, rdata);
  }

  static byte[] txt(String... strings) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (String s : strings) {
      byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
      out.write(b.length);
      out.write(b, 0, b.length);
    }
    return out.toByteArray();
  }

  static byte[] cname(String target) {
    return DnsName.of(target).toWire();
  }

  private static void write16(ByteArrayOutputStream out, int v) {
    out.write(v >>> 8);
    out.write(v);
  }

  private static void write32(ByteArrayOutputStream out, long v) {
    write16(out, (int) (v >>> 16));
    write16(out, (int) v);
  }

}
