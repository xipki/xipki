// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.dns.DnsException;
import org.xipki.ca.gateway.dns.DnsException.Reason;
import org.xipki.ca.gateway.dns.DnsMessage;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.ca.gateway.dns.DnsTransport;
import org.xipki.ca.gateway.dns.WireReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * DNSSEC validator for positive answers only.
 * <p>
 * An RRset is secure if it is signed by a DNSKEY of the signer zone, whose DNSKEY
 * RRset is signed by a key that matches a validated DS record in the parent zone (or
 * a trust anchor), and so on up to a trust anchor. Negative answers (NXDOMAIN, NODATA)
 * and insecure delegations are never accepted, so no NSEC/NSEC3 proofs are needed.
 * Answers expanded from wildcards are rejected for the same reason.
 * <p>
 * The queries are sent with DO=1 and CD=1, so the resolver does not need to validate,
 * and the validation does not depend on the path to the resolver.
 *
 * @author Lijun Liao (xipki)
 */
public class DnssecValidator {

  private static final Logger LOG = LoggerFactory.getLogger(DnssecValidator.class);

  static final int MAX_SIGNATURES_PER_RRSET = 8;

  static final int MAX_KEYS_PER_TAG = 4;

  static final int MAX_ZONE_DEPTH = 8;

  static final long MAX_CACHE_TTL_SECONDS = 900;

  static final int MAX_CACHE_SIZE = 1000;

  static final int DNSKEY_FLAG_ZONE = 0x0100;

  static final int DNSKEY_FLAG_REVOKE = 0x0080;

  /**
   * Parsed RRSIG RDATA (RFC 4034 section 3.1).
   */
  static final class Rrsig {

    final int typeCovered;
    final int algorithm;
    final int labels;
    final long originalTtl;
    final long expiration;
    final long inception;
    final int keyTag;
    final DnsName signer;
    final byte[] signature;
    /** RDATA without the signature, the first part of the signed data. */
    final byte[] signedPart;

    Rrsig(byte[] rdata) throws DnsException {
      WireReader r = new WireReader(rdata);
      typeCovered = r.u16();
      algorithm = r.u8();
      labels = r.u8();
      originalTtl = r.u32();
      expiration = r.u32();
      inception = r.u32();
      keyTag = r.u16();
      signer = r.name();
      signedPart = Arrays.copyOf(rdata, r.position());
      signature = r.bytes(r.remaining());
    }

  }

  /**
   * Parsed DNSKEY RDATA (RFC 4034 section 2.1).
   */
  static final class Dnskey {

    final int flags;
    final int protocol;
    final int algorithm;
    final byte[] publicKey;
    final byte[] rdata;
    final int keyTag;
    /** Expiry of the validation (epoch seconds), used by the key cache. */
    long expiresAtSeconds;

    Dnskey(byte[] rdata) throws DnsException {
      WireReader r = new WireReader(rdata);
      flags = r.u16();
      protocol = r.u8();
      algorithm = r.u8();
      publicKey = r.bytes(r.remaining());
      this.rdata = rdata;
      this.keyTag = keyTag(rdata);
    }

    /**
     * Returns whether the key may be used to verify signatures: zone key, protocol 3,
     * not revoked (RFC 4034 section 2.1, RFC 5011 section 7).
     */
    boolean usable() {
      return (flags & DNSKEY_FLAG_ZONE) != 0 && (flags & DNSKEY_FLAG_REVOKE) == 0
          && protocol == 3;
    }

    /**
     * Key tag as in RFC 4034 Appendix B.
     */
    static int keyTag(byte[] rdata) {
      long ac = 0;
      for (int i = 0; i < rdata.length; i++) {
        ac += ((i & 1) == 0) ? (rdata[i] & 0xFF) << 8 : rdata[i] & 0xFF;
      }
      ac += (ac >> 16) & 0xFFFF;
      return (int) (ac & 0xFFFF);
    }

  }

  private final DnsTransport transport;

  private volatile Map<DnsName, List<DnsRecord>> trustAnchors;

  private final Clock clock;

  // validated DNSKEY RRsets; the expiry is stored in the first key
  private final Map<DnsName, List<Dnskey>> keyCache = new HashMap<>();

  /**
   * Constructor.
   *
   * @param transport the transport, must request DNSSEC records (DO=1, CD=1).
   * @param trustAnchors the trust anchors, DS or DNSKEY records, usually of the root.
   * @param clock the clock to check the validity period of the signatures.
   */
  public DnssecValidator(DnsTransport transport, List<DnsRecord> trustAnchors, Clock clock) {
    this.transport = transport;
    this.clock = clock;
    this.trustAnchors = toMap(trustAnchors);
  }

  /**
   * Replaces the trust anchors and clears the cache of validated keys, which were
   * validated against the old trust anchors.
   *
   * @param trustAnchors the new trust anchors, DS or DNSKEY records.
   * @throws IllegalArgumentException if the trust anchors are empty or invalid. The old
   *         trust anchors are kept.
   */
  public void setTrustAnchors(List<DnsRecord> trustAnchors) {
    Map<DnsName, List<DnsRecord>> map = toMap(trustAnchors);
    synchronized (keyCache) {
      this.trustAnchors = map;
      keyCache.clear();
    }
  }

  private static Map<DnsName, List<DnsRecord>> toMap(List<DnsRecord> trustAnchors) {
    Map<DnsName, List<DnsRecord>> map = new HashMap<>();
    for (DnsRecord anchor : trustAnchors) {
      if (anchor.type() != DnsRecord.TYPE_DS && anchor.type() != DnsRecord.TYPE_DNSKEY) {
        throw new IllegalArgumentException("trust anchor is neither DS nor DNSKEY");
      }
      map.computeIfAbsent(anchor.name(), k -> new ArrayList<>()).add(anchor);
    }

    if (map.isEmpty()) {
      throw new IllegalArgumentException("no trust anchors");
    }
    return map;
  }

  /**
   * Validates the RRset.
   *
   * @param owner the owner name of the RRset.
   * @param type the type of the RRset.
   * @param rrset the records of the RRset, from the answer section, owner {@code owner}.
   * @param rrsigs the RRSIG records with owner {@code owner} that cover {@code type}.
   * @param budget the budget of the whole lookup.
   * @throws DnsException if the RRset is not secure.
   */
  public void validate(DnsName owner, int type, List<DnsRecord> rrset, List<DnsRecord> rrsigs,
                       ValidationBudget budget) throws DnsException {
    verifyRrset(owner, type, rrset, rrsigs, null, budget, 0);
  }

  /**
   * Verifies the RRset with one of its RRSIGs and returns the time (epoch seconds) until
   * which the result may be cached.
   *
   * @param keys the keys to verify with, or {@code null} to use the validated keys of
   *        the signer zone of each RRSIG.
   */
  private long verifyRrset(DnsName owner, int type, List<DnsRecord> rrset,
                           List<DnsRecord> rrsigs, List<Dnskey> keys, ValidationBudget budget,
                           int depth) throws DnsException {
    checkRrset(owner, type, rrset);
    if (rrsigs.isEmpty()) {
      throw new DnsException(Reason.MISSING_RRSIG, "no RRSIG for " + owner + "/" + type);
    }

    DnsException last = null;
    int tried = 0;
    for (DnsRecord sigRecord : rrsigs) {
      if (tried++ >= MAX_SIGNATURES_PER_RRSET) {
        throw new DnsException(Reason.LIMIT_EXCEEDED, "too many RRSIGs for " + owner);
      }

      try {
        Rrsig sig = new Rrsig(sigRecord.rdata());
        checkRrsig(owner, type, sigRecord, sig);
        verify(owner, type, rrset, sig,
            keys != null ? keys : zoneKeys(sig.signer, budget, depth + 1), budget);
        return Math.min(nowSeconds() + ttl(rrset, sig), sig.expiration);
      } catch (DnsException ex) {
        if (ex.reason() == Reason.LIMIT_EXCEEDED) {
          throw ex;
        }
        last = ex;
      }
    }
    throw last;
  }

  private static void checkRrset(DnsName owner, int type, List<DnsRecord> rrset)
      throws DnsException {
    if (rrset.isEmpty()) {
      throw new DnsException(Reason.MALFORMED, "empty RRset " + owner + "/" + type);
    }

    for (DnsRecord rr : rrset) {
      if (!rr.name().equals(owner) || rr.type() != type) {
        throw new DnsException(Reason.MALFORMED, "record does not belong to RRset");
      }
      if (rr.dclass() != DnsRecord.CLASS_IN) {
        throw new DnsException(Reason.RRSIG_MISMATCH, "class is not IN");
      }
    }
  }

  /**
   * The checks of RFC 4035 section 5.3.1 that do not need the key.
   */
  private void checkRrsig(DnsName owner, int type, DnsRecord sigRecord, Rrsig sig)
      throws DnsException {
    if (!sigRecord.name().equals(owner) || sigRecord.type() != DnsRecord.TYPE_RRSIG) {
      throw new DnsException(Reason.MALFORMED, "RRSIG does not belong to RRset");
    }

    if (sigRecord.dclass() != DnsRecord.CLASS_IN || sig.typeCovered != type) {
      throw new DnsException(Reason.RRSIG_MISMATCH,
          "RRSIG covers type " + sig.typeCovered + " instead of " + type);
    }

    int ownerLabels = owner.labelCount();
    if (sig.labels < ownerLabels) {
      throw new DnsException(Reason.WILDCARD, owner + " was expanded from a wildcard");
    } else if (sig.labels > ownerLabels) {
      throw new DnsException(Reason.INVALID_LABELS, "RRSIG labels > labels of " + owner);
    }

    boolean signerValid;
    if (type == DnsRecord.TYPE_DS) {
      // The DS RRset is signed by the parent zone.
      signerValid = owner.isProperSubdomainOf(sig.signer);
    } else if (type == DnsRecord.TYPE_DNSKEY) {
      signerValid = owner.equals(sig.signer);
    } else {
      signerValid = owner.isSubdomainOf(sig.signer);
    }

    if (!signerValid) {
      throw new DnsException(Reason.INVALID_SIGNER,
          "signer " + sig.signer + " may not sign " + owner + "/" + type);
    }

    // serial number arithmetic, RFC 4034 section 3.1.5
    int now = (int) nowSeconds();
    if ((int) (now - sig.inception) < 0) {
      throw new DnsException(Reason.SIGNATURE_NOT_YET_VALID, "RRSIG of " + owner);
    }
    if ((int) (sig.expiration - now) < 0) {
      throw new DnsException(Reason.SIGNATURE_EXPIRED, "RRSIG of " + owner);
    }

    if (!DnssecCrypto.isSupportedAlgorithm(sig.algorithm)) {
      throw new DnsException(Reason.UNSUPPORTED_ALGORITHM,
          "algorithm " + sig.algorithm + " of RRSIG of " + owner);
    }
  }

  private void verify(DnsName owner, int type, List<DnsRecord> rrset, Rrsig sig,
                      List<Dnskey> keys, ValidationBudget budget) throws DnsException {
    List<Dnskey> candidates = new ArrayList<>(2);
    boolean unusableMatch = false;
    for (Dnskey key : keys) {
      if (key.keyTag == sig.keyTag && key.algorithm == sig.algorithm) {
        if (key.usable()) {
          candidates.add(key);
        } else {
          unusableMatch = true;
        }
      }
    }

    if (candidates.size() > MAX_KEYS_PER_TAG) {
      throw new DnsException(Reason.LIMIT_EXCEEDED, "too many keys with tag " + sig.keyTag);
    }

    if (candidates.isEmpty()) {
      throw new DnsException(unusableMatch ? Reason.DNSKEY_INVALID : Reason.NO_MATCHING_KEY,
          "no usable DNSKEY " + sig.keyTag + " of " + sig.signer);
    }

    byte[] data = signedData(owner, type, rrset, sig);
    for (Dnskey key : candidates) {
      budget.countVerification();
      if (DnssecCrypto.verify(sig.algorithm, key.publicKey, data, sig.signature)) {
        return;
      }
    }
    throw new DnsException(Reason.INVALID_SIGNATURE, "RRSIG of " + owner + "/" + type);
  }

  /**
   * Returns the signed data of RFC 4034 section 3.1.8.1: the RRSIG RDATA without the
   * signature, followed by the records in canonical form and order.
   */
  static byte[] signedData(DnsName owner, int type, List<DnsRecord> rrset, Rrsig sig) {
    // canonical order: sorted by RDATA as left-justified unsigned octet sequences,
    // duplicates removed
    TreeMap<byte[], DnsRecord> sorted = new TreeMap<>(DnssecValidator::compareUnsigned);
    for (DnsRecord rr : rrset) {
      sorted.put(rr.rdata(), rr);
    }

    byte[] ownerWire = owner.toWire();
    ByteArrayOutputStream out = new ByteArrayOutputStream(512);
    out.write(sig.signedPart, 0, sig.signedPart.length);
    for (byte[] rdata : sorted.keySet()) {
      out.write(ownerWire, 0, ownerWire.length);
      DnsMessage.write16(out, type);
      DnsMessage.write16(out, DnsRecord.CLASS_IN);
      DnsMessage.write16(out, (int) (sig.originalTtl >>> 16));
      DnsMessage.write16(out, (int) sig.originalTtl);
      DnsMessage.write16(out, rdata.length);
      out.write(rdata, 0, rdata.length);
    }
    return out.toByteArray();
  }

  private static int compareUnsigned(byte[] a, byte[] b) {
    int len = Math.min(a.length, b.length);
    for (int i = 0; i < len; i++) {
      int d = (a[i] & 0xFF) - (b[i] & 0xFF);
      if (d != 0) {
        return d;
      }
    }
    return a.length - b.length;
  }

  /**
   * Returns the validated DNSKEYs of the zone, including unusable ones.
   */
  private List<Dnskey> zoneKeys(DnsName zone, ValidationBudget budget, int depth)
      throws DnsException {
    if (depth > MAX_ZONE_DEPTH) {
      throw new DnsException(Reason.LIMIT_EXCEEDED, "chain of trust too long at " + zone);
    }

    // keys validated against replaced trust anchors must not be cached
    Map<DnsName, List<DnsRecord>> anchorsSnapshot = trustAnchors;
    synchronized (keyCache) {
      List<Dnskey> cached = keyCache.get(zone);
      if (cached != null) {
        if (cached.get(0).expiresAtSeconds > nowSeconds()) {
          return cached;
        }
        keyCache.remove(zone);
      }
    }

    // 1. the trusted DS records (or DNSKEY trust anchors)
    List<byte[]> dsSet = new ArrayList<>();
    List<byte[]> anchorKeys = new ArrayList<>();
    long expiresAt = nowSeconds() + MAX_CACHE_TTL_SECONDS;

    List<DnsRecord> anchors = anchorsSnapshot.get(zone);
    if (anchors != null) {
      for (DnsRecord anchor : anchors) {
        (anchor.type() == DnsRecord.TYPE_DS ? dsSet : anchorKeys).add(anchor.rdata());
      }
    } else if (zone.isRoot()) {
      throw new DnsException(Reason.NO_TRUST_ANCHOR, "chain of trust ends at the root");
    } else {
      DnsMessage dsResponse = query(zone, DnsRecord.TYPE_DS, budget);
      List<DnsRecord> dsRecords = dsResponse.answer(zone, DnsRecord.TYPE_DS);
      if (dsRecords.isEmpty()) {
        throw new DnsException(Reason.NO_DS, "no DS for " + zone);
      }
      expiresAt = Math.min(expiresAt, verifyRrset(zone, DnsRecord.TYPE_DS, dsRecords,
          dsResponse.rrsigs(zone, DnsRecord.TYPE_DS), null, budget, depth));
      for (DnsRecord rr : dsRecords) {
        dsSet.add(rr.rdata());
      }
    }

    // DS RDATA: key tag (2), algorithm (1), digest type (1), digest
    List<byte[]> supportedDsSet = new ArrayList<>(dsSet.size());
    for (byte[] ds : dsSet) {
      if (ds.length > 4 && DnssecCrypto.isSupportedAlgorithm(ds[2] & 0xFF)
          && DnssecCrypto.isSupportedDigestType(ds[3] & 0xFF)) {
        supportedDsSet.add(ds);
      }
    }

    if (supportedDsSet.isEmpty() && anchorKeys.isEmpty()) {
      throw new DnsException(Reason.UNSUPPORTED_ALGORITHM,
          "no DS of " + zone + " with supported algorithm and digest type");
    }

    // 2. the DNSKEY RRset
    DnsMessage keyResponse = query(zone, DnsRecord.TYPE_DNSKEY, budget);
    List<DnsRecord> keyRecords = keyResponse.answer(zone, DnsRecord.TYPE_DNSKEY);
    if (keyRecords.isEmpty()) {
      throw new DnsException(Reason.NO_DNSKEY, "no DNSKEY for " + zone);
    }

    List<Dnskey> keys = new ArrayList<>(keyRecords.size());
    for (DnsRecord rr : keyRecords) {
      keys.add(new Dnskey(rr.rdata()));
    }

    // 3. the keys that match the trusted DS records or trust anchors
    List<Dnskey> entryKeys = new ArrayList<>(2);
    for (Dnskey key : keys) {
      if (key.usable() && isTrusted(zone, key, supportedDsSet, anchorKeys)) {
        entryKeys.add(key);
      }
    }

    if (entryKeys.isEmpty()) {
      throw new DnsException(Reason.DS_MISMATCH, "no DNSKEY of " + zone + " matches DS");
    }

    // 4. the DNSKEY RRset must be signed by one of the entry keys
    expiresAt = Math.min(expiresAt, verifyRrset(zone, DnsRecord.TYPE_DNSKEY, keyRecords,
        keyResponse.rrsigs(zone, DnsRecord.TYPE_DNSKEY), entryKeys, budget, depth));
    keys.get(0).expiresAtSeconds = expiresAt;

    List<Dnskey> result = Collections.unmodifiableList(keys);
    synchronized (keyCache) {
      if (trustAnchors == anchorsSnapshot) {
        if (keyCache.size() >= MAX_CACHE_SIZE) {
          keyCache.clear();
        }
        keyCache.put(zone, result);
      }
    }
    LOG.debug("validated DNSKEY RRset of {}", zone);
    return result;
  }

  private static boolean isTrusted(DnsName zone, Dnskey key, List<byte[]> dsSet,
                                   List<byte[]> anchorKeys) {
    for (byte[] anchorKey : anchorKeys) {
      if (Arrays.equals(anchorKey, key.rdata)) {
        return true;
      }
    }

    for (byte[] ds : dsSet) {
      int keyTag = ((ds[0] & 0xFF) << 8) | (ds[1] & 0xFF);
      if (keyTag == key.keyTag && (ds[2] & 0xFF) == key.algorithm
          && MessageDigest.isEqual(Arrays.copyOfRange(ds, 4, ds.length),
              DnssecCrypto.dsDigest(ds[3] & 0xFF, zone, key.rdata))) {
        return true;
      }
    }
    return false;
  }

  private DnsMessage query(DnsName name, int type, ValidationBudget budget)
      throws DnsException {
    budget.countQuery();
    DnsMessage response;
    try {
      response = transport.query(name, type);
    } catch (IOException ex) {
      throw new DnsException(Reason.QUERY_FAILED,
          "query " + name + "/" + type + " failed: " + ex.getMessage());
    }

    if (response.rcode() != DnsMessage.RCODE_NOERROR) {
      throw new DnsException(Reason.QUERY_FAILED,
          "query " + name + "/" + type + " returned " + DnsMessage.rcodeText(response.rcode()));
    }
    return response;
  }

  private static long ttl(List<DnsRecord> rrset, Rrsig sig) {
    long ttl = Math.min(sig.originalTtl, MAX_CACHE_TTL_SECONDS);
    for (DnsRecord rr : rrset) {
      ttl = Math.min(ttl, rr.ttl());
    }
    return ttl;
  }

  private long nowSeconds() {
    return clock.millis() / 1000;
  }

}
