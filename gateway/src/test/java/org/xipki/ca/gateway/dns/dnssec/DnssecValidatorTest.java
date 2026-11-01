// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.ca.gateway.dns.DnsClient;
import org.xipki.ca.gateway.dns.DnsException;
import org.xipki.ca.gateway.dns.DnsMessage;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.ca.gateway.dns.DnsException.Reason;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.xipki.ca.gateway.dns.DnsRecord.TYPE_CNAME;
import static org.xipki.ca.gateway.dns.DnsRecord.TYPE_DNSKEY;
import static org.xipki.ca.gateway.dns.DnsRecord.TYPE_DS;
import static org.xipki.ca.gateway.dns.DnsRecord.TYPE_TXT;

/**
 * JUnit tests of {@link DnssecValidator}: one test per check of the validator, each
 * against an otherwise valid chain of trust.
 *
 * @author Lijun Liao (xipki)
 */
public class DnssecValidatorTest {

  private interface SigModifier {
    void modify(TestTree.Sig sig) throws Exception;
  }

  private interface Action {
    void run() throws Exception;
  }

  private static final String ACME_NAME = "_acme-challenge.example.test";

  private static final DnsName ACME = DnsName.of(ACME_NAME);

  private static final DnsName EXAMPLE = DnsName.of("example.test");

  private TestTree tree;

  @Before
  public void init() throws Exception {
    tree = new TestTree();
    tree.addZone(".", DnssecCrypto.ECDSAP256SHA256);
    tree.addZone("test.", DnssecCrypto.RSASHA256);
    tree.addZone("example.test.", DnssecCrypto.ED25519);
    tree.addData("example.test.", ACME_NAME, TYPE_TXT, TestTree.txt("token"));
    tree.build();
  }

  private List<String> queryTxt() throws Exception {
    return new DnsClient(tree, tree.validator()).queryTxt(ACME_NAME);
  }

  private void assertValid() throws Exception {
    Assert.assertEquals(Collections.singletonList("token"), queryTxt());
  }

  private static void assertReason(Reason expected, Action action) throws Exception {
    try {
      action.run();
      Assert.fail("expected DnsException " + expected);
    } catch (DnsException ex) {
      Assert.assertEquals(ex.getMessage(), expected, ex.reason());
    }
  }

  private void assertTxtRejected(Reason expected) throws Exception {
    assertReason(expected, this::queryTxt);
  }

  private List<DnsRecord> rrset(DnsName owner, int type) {
    List<DnsRecord> ret = new ArrayList<>();
    for (DnsRecord rr : tree.answer(owner, type)) {
      if (rr.type() == type) {
        ret.add(rr);
      }
    }
    return ret;
  }

  /** Replaces the RRSIG of the TXT RRset by a modified one. */
  private void resignTxt(SigModifier modifier) throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    TestTree.Sig sig = tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name);
    modifier.modify(sig);
    tree.put(ACME, TYPE_TXT, txt, sig.build());
  }

  // ------------------------------------------------------------------
  // positive cases
  // ------------------------------------------------------------------

  @Test
  public void validChain() throws Exception {
    assertValid();
  }

  @Test
  public void allAlgorithms() throws Exception {
    int[] algs = {DnssecCrypto.RSASHA256, DnssecCrypto.RSASHA512,
        DnssecCrypto.ECDSAP256SHA256, DnssecCrypto.ECDSAP384SHA384,
        DnssecCrypto.ED25519, DnssecCrypto.ED448};
    for (int alg : algs) {
      TestTree t = new TestTree();
      t.addZone(".", alg);
      t.addZone("test.", alg);
      t.addData("test.", "_acme-challenge.test", TYPE_TXT, TestTree.txt("v" + alg));
      t.build();
      Assert.assertEquals("algorithm " + alg, Collections.singletonList("v" + alg),
          new DnsClient(t, t.validator()).queryTxt("_acme-challenge.test"));
    }
  }

  @Test
  public void severalTxtRecords() throws Exception {
    tree.addData("example.test.", "multi.example.test", TYPE_TXT,
        TestTree.txt("abc", "def"), TestTree.txt("token"));
    tree.build();
    List<String> values = new DnsClient(tree, tree.validator()).queryTxt("multi.example.test");
    Assert.assertEquals(2, values.size());
    Assert.assertTrue(values.contains("abcdef"));
    Assert.assertTrue(values.contains("token"));
  }

  @Test
  public void cnameToOtherSignedZone() throws Exception {
    tree.addZone("other.test.", DnssecCrypto.ECDSAP384SHA384);
    tree.addData("example.test.", "_acme-challenge.www.example.test", TYPE_CNAME,
        TestTree.cname("_acme.other.test"));
    tree.addData("other.test.", "_acme.other.test", TYPE_TXT, TestTree.txt("delegated"));
    tree.build();
    Assert.assertEquals(Collections.singletonList("delegated"),
        new DnsClient(tree, tree.validator()).queryTxt("_acme-challenge.www.example.test"));
  }

  @Test
  public void bogusSignatureBeforeValidOne() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    TestTree.Sig bogus = tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name);
    bogus.keyTag = (bogus.keyTag + 1) & 0xFFFF;
    tree.put(ACME, TYPE_TXT, txt, bogus.build(),
        tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name).build());
    assertValid();
  }

  @Test
  public void keysAreCached() throws Exception {
    DnssecValidator validator = tree.validator();
    DnsClient client = new DnsClient(tree, validator);
    client.queryTxt(ACME_NAME);
    int first = tree.queryCount;
    client.queryTxt(ACME_NAME);
    // only the TXT query is sent again
    Assert.assertEquals(first + 1, tree.queryCount);

    // after the cache TTL, the keys are fetched again
    tree.clock.millis += (DnssecValidator.MAX_CACHE_TTL_SECONDS + 1) * 1000;
    client.queryTxt(ACME_NAME);
    Assert.assertEquals(2 * first + 1, tree.queryCount);
  }

  @Test
  public void dsSignedByAncestorAboveParent() throws Exception {
    // Every ancestor zone is trusted for its whole subtree, so a DS signed by the root
    // instead of "test." is accepted (no NSEC proofs of the zone cuts are validated).
    TestTree.Zone root = tree.zone(".");
    List<DnsRecord> ds = rrset(EXAMPLE, TYPE_DS);
    tree.put(EXAMPLE, TYPE_DS, ds,
        tree.sig(EXAMPLE, TYPE_DS, ds, root.zsk, DnsName.ROOT).build());
    assertValid();
  }

  // ------------------------------------------------------------------
  // check 1: only relevant records
  // ------------------------------------------------------------------

  @Test
  public void recordOfOtherOwnerIgnored() throws Exception {
    DnsName other = DnsName.of("evil.example.test");
    tree.put(ACME, TYPE_TXT, Collections.singletonList(
        TestTree.rr(other, TYPE_TXT, TestTree.txt("token"))));
    Assert.assertEquals(Collections.emptyList(), queryTxt());
  }

  @Test
  public void dnskeyInAdditionalSectionIgnored() throws Exception {
    List<DnsRecord> keys = tree.answer(EXAMPLE, TYPE_DNSKEY);
    tree.put(EXAMPLE, TYPE_DNSKEY, Collections.emptyList());
    tree.putAdditional(EXAMPLE, TYPE_DNSKEY, keys);
    assertTxtRejected(Reason.NO_DNSKEY);
  }

  @Test
  public void twoCnames() throws Exception {
    tree.addData("example.test.", "two.example.test", TYPE_CNAME,
        TestTree.cname("a.example.test"), TestTree.cname("b.example.test"));
    tree.build();
    try {
      new DnsClient(tree, tree.validator()).queryTxt("two.example.test");
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertNull("not a DNSSEC failure", ex.reason());
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("more than one CNAME"));
    }
  }

  @Test
  public void dname() throws Exception {
    DnsRecord dname = TestTree.rr(EXAMPLE, DnsRecord.TYPE_DNAME,
        DnsName.of("other.test").toWire());
    DnsRecord cname = TestTree.rr(ACME, TYPE_CNAME, TestTree.cname("_acme-challenge.other.test"));
    tree.put(ACME, TYPE_TXT, Arrays.asList(dname, cname));
    assertTxtRejected(Reason.DNAME);
  }

  // ------------------------------------------------------------------
  // check 2: RRSIG matches the RRset
  // ------------------------------------------------------------------

  @Test
  public void rrsigOfOtherType() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    TestTree.Sig sig = tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name);
    sig.typeCovered = 1; // A
    DnsRecord rrsig = sig.build();
    assertReason(Reason.RRSIG_MISMATCH, () -> tree.validator().validate(ACME, TYPE_TXT, txt,
        Collections.singletonList(rrsig), new ValidationBudget()));

    // via the client, the RRSIG is not selected at all
    tree.put(ACME, TYPE_TXT, txt, rrsig);
    assertTxtRejected(Reason.MISSING_RRSIG);
  }

  @Test
  public void classNotIn() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> txt = Collections.singletonList(
        new DnsRecord(ACME, TYPE_TXT, 3, TestTree.TTL, TestTree.txt("token")));
    TestTree.Sig sig = tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name);
    sig.dclass = 3;
    DnsRecord rrsig = sig.build();
    assertReason(Reason.RRSIG_MISMATCH, () -> tree.validator().validate(ACME, TYPE_TXT, txt,
        Collections.singletonList(rrsig), new ValidationBudget()));
  }

  @Test
  public void missingRrsig() throws Exception {
    tree.put(ACME, TYPE_TXT, rrset(ACME, TYPE_TXT));
    assertTxtRejected(Reason.MISSING_RRSIG);
  }

  // ------------------------------------------------------------------
  // check 3: signer is the owner or an ancestor of it
  // ------------------------------------------------------------------

  @Test
  public void signedByOtherZoneWithValidChain() throws Exception {
    tree.addZone("evil.test.", DnssecCrypto.ED25519);
    tree.build();
    TestTree.Zone evil = tree.zone("evil.test.");
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    tree.put(ACME, TYPE_TXT, txt, tree.sig(ACME, TYPE_TXT, txt, evil.zsk, evil.name).build());
    assertTxtRejected(Reason.INVALID_SIGNER);
  }

  @Test
  public void signerBelowOwner() throws Exception {
    resignTxt(sig -> sig.signer = DnsName.of("sub." + ACME_NAME));
    assertTxtRejected(Reason.INVALID_SIGNER);
  }

  // ------------------------------------------------------------------
  // check 4: labels and validity period
  // ------------------------------------------------------------------

  @Test
  public void wildcardExpansion() throws Exception {
    resignTxt(sig -> sig.labels = ACME.labelCount() - 1);
    assertTxtRejected(Reason.WILDCARD);
  }

  @Test
  public void labelsTooLarge() throws Exception {
    resignTxt(sig -> sig.labels = ACME.labelCount() + 1);
    assertTxtRejected(Reason.INVALID_LABELS);
  }

  @Test
  public void expiredSignature() throws Exception {
    resignTxt(sig -> sig.expiration = TestTree.NOW - 1);
    assertTxtRejected(Reason.SIGNATURE_EXPIRED);
  }

  @Test
  public void signatureNotYetValid() throws Exception {
    resignTxt(sig -> sig.inception = TestTree.NOW + 60);
    assertTxtRejected(Reason.SIGNATURE_NOT_YET_VALID);
  }

  // ------------------------------------------------------------------
  // check 5: DNSKEY properties, key tag and algorithm
  // ------------------------------------------------------------------

  @Test
  public void zoneKeyFlagCleared() throws Exception {
    tree.zone("example.test.").zsk.flags = 0;
    tree.build();
    assertTxtRejected(Reason.DNSKEY_INVALID);
  }

  @Test
  public void revokedKey() throws Exception {
    tree.zone("example.test.").zsk.flags = TestKey.FLAGS_ZSK | DnssecValidator.DNSKEY_FLAG_REVOKE;
    tree.build();
    assertTxtRejected(Reason.DNSKEY_INVALID);
  }

  @Test
  public void protocolNot3() throws Exception {
    tree.zone("example.test.").zsk.protocol = 2;
    tree.build();
    assertTxtRejected(Reason.DNSKEY_INVALID);
  }

  @Test
  public void algorithmMismatch() throws Exception {
    resignTxt(sig -> sig.algorithm = DnssecCrypto.ECDSAP256SHA256);
    assertTxtRejected(Reason.NO_MATCHING_KEY);
  }

  @Test
  public void keyTagMismatch() throws Exception {
    resignTxt(sig -> sig.keyTag = (sig.keyTag + 1) & 0xFFFF);
    assertTxtRejected(Reason.NO_MATCHING_KEY);
  }

  @Test
  public void invalidSignature() throws Exception {
    List<DnsRecord> answer = tree.answer(ACME, TYPE_TXT);
    DnsRecord rrsig = answer.get(1);
    byte[] rdata = rrsig.rdata().clone();
    rdata[rdata.length - 1] ^= 1;
    tree.put(ACME, TYPE_TXT, Collections.singletonList(answer.get(0)),
        new DnsRecord(ACME, DnsRecord.TYPE_RRSIG, DnsRecord.CLASS_IN, rrsig.ttl(), rdata));
    assertTxtRejected(Reason.INVALID_SIGNATURE);
  }

  @Test
  public void modifiedData() throws Exception {
    List<DnsRecord> answer = tree.answer(ACME, TYPE_TXT);
    tree.put(ACME, TYPE_TXT, Collections.singletonList(
        TestTree.rr(ACME, TYPE_TXT, TestTree.txt("forged"))), answer.get(1));
    assertTxtRejected(Reason.INVALID_SIGNATURE);
  }

  // ------------------------------------------------------------------
  // check 6: DNSKEY RRset linked to DS
  // ------------------------------------------------------------------

  @Test
  public void dnskeyRrsetSignedByZskOnly() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> keys = rrset(EXAMPLE, TYPE_DNSKEY);
    tree.put(EXAMPLE, TYPE_DNSKEY, keys,
        tree.sig(EXAMPLE, TYPE_DNSKEY, keys, zone.zsk, zone.name).build());
    assertTxtRejected(Reason.NO_MATCHING_KEY);
  }

  @Test
  public void dsDigestModified() throws Exception {
    TestTree.Zone parent = tree.zone("test.");
    DnsRecord ds = rrset(EXAMPLE, TYPE_DS).get(0);
    byte[] rdata = ds.rdata().clone();
    rdata[rdata.length - 1] ^= 1;
    List<DnsRecord> forged = Collections.singletonList(TestTree.rr(EXAMPLE, TYPE_DS, rdata));
    tree.put(EXAMPLE, TYPE_DS, forged,
        tree.sig(EXAMPLE, TYPE_DS, forged, parent.zsk, parent.name).build());
    assertTxtRejected(Reason.DS_MISMATCH);
  }

  @Test
  public void dsDigestTypeSha1() throws Exception {
    tree.zone("example.test.").dsDigestType = 1;
    tree.build();
    assertTxtRejected(Reason.UNSUPPORTED_ALGORITHM);
  }

  @Test
  public void forgedDnskeyRrset() throws Exception {
    // attacker replaces the DNSKEY RRset by own keys, self-signed
    TestTree attacker = new TestTree("attacker");
    attacker.addZone(".", DnssecCrypto.ED25519);
    TestTree.Zone fake = attacker.addZone("example.test.", DnssecCrypto.ED25519);
    attacker.build();
    tree.put(EXAMPLE, TYPE_DNSKEY, attacker.answer(EXAMPLE, TYPE_DNSKEY));
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    tree.put(ACME, TYPE_TXT, txt, tree.sig(ACME, TYPE_TXT, txt, fake.zsk, EXAMPLE).build());
    assertTxtRejected(Reason.DS_MISMATCH);
  }

  // ------------------------------------------------------------------
  // check 7: chain of trust
  // ------------------------------------------------------------------

  @Test
  public void dsSignedByChild() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> ds = rrset(EXAMPLE, TYPE_DS);
    tree.put(EXAMPLE, TYPE_DS, ds, tree.sig(EXAMPLE, TYPE_DS, ds, zone.zsk, zone.name).build());
    assertTxtRejected(Reason.INVALID_SIGNER);
  }

  @Test
  public void missingDs() throws Exception {
    tree.put(EXAMPLE, TYPE_DS, Collections.emptyList());
    assertTxtRejected(Reason.NO_DS);
  }

  @Test
  public void unknownRootKey() throws Exception {
    TestTree other = new TestTree("other");
    other.addZone(".", DnssecCrypto.ED448);
    DnssecValidator validator = new DnssecValidator(tree, other.trustAnchors(), tree.clock);
    assertReason(Reason.DS_MISMATCH,
        () -> new DnsClient(tree, validator).queryTxt(ACME_NAME));
  }

  @Test
  public void noTrustAnchorForRoot() throws Exception {
    DnsRecord anchor = TestTree.rr(DnsName.of("other"), TYPE_DS, new byte[]{0, 1, 13, 2, 0});
    DnssecValidator validator = new DnssecValidator(tree,
        Collections.singletonList(anchor), tree.clock);
    assertReason(Reason.NO_TRUST_ANCHOR,
        () -> new DnsClient(tree, validator).queryTxt(ACME_NAME));
  }

  @Test
  public void trustAnchorAsDnskey() throws Exception {
    DnsRecord anchor = TestTree.rr(DnsName.ROOT, TYPE_DNSKEY,
        tree.zone(".").ksk.dnskeyRdata());
    DnssecValidator validator = new DnssecValidator(tree,
        Collections.singletonList(anchor), tree.clock);
    Assert.assertEquals(Collections.singletonList("token"),
        new DnsClient(tree, validator).queryTxt(ACME_NAME));
  }

  @Test
  public void failedKeyQuery() throws Exception {
    tree.setRcode(EXAMPLE, TYPE_DNSKEY, DnsMessage.RCODE_SERVFAIL);
    assertTxtRejected(Reason.QUERY_FAILED);
  }

  // ------------------------------------------------------------------
  // check 8: limits, algorithms and cache
  // ------------------------------------------------------------------

  @Test
  public void tooManyRrsigs() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    List<DnsRecord> txt = rrset(ACME, TYPE_TXT);
    DnsRecord[] sigs = new DnsRecord[DnssecValidator.MAX_SIGNATURES_PER_RRSET + 1];
    for (int i = 0; i < sigs.length; i++) {
      TestTree.Sig sig = tree.sig(ACME, TYPE_TXT, txt, zone.zsk, zone.name);
      sig.originalTtl = 100 + i; // makes each signature different and invalid
      DnsRecord built = sig.build();
      byte[] rdata = built.rdata().clone();
      rdata[7] = (byte) (TestTree.TTL & 0xFF); // claim TTL 3600: signature no longer valid
      sigs[i] = new DnsRecord(ACME, DnsRecord.TYPE_RRSIG, DnsRecord.CLASS_IN, TestTree.TTL,
          rdata);
    }
    tree.put(ACME, TYPE_TXT, txt, sigs);
    assertTxtRejected(Reason.LIMIT_EXCEEDED);
  }

  @Test
  public void tooManyKeysWithSameTag() throws Exception {
    TestTree.Zone zone = tree.zone("example.test.");
    int tag = zone.zsk.keyTag();
    for (int k = 1; zone.extraKeys.size() < DnssecValidator.MAX_KEYS_PER_TAG; k++) {
      TestKey extra = new TestKey(zone.zsk.algorithm, TestKey.FLAGS_ZSK, zone.zsk.keyPair);
      byte[] pk = zone.zsk.publicKey.clone();
      // +k at one even RDATA offset and -k at another keeps the key tag
      pk[0] = (byte) (pk[0] + k);
      pk[2] = (byte) (pk[2] - k);
      extra.publicKey = pk;
      if (extra.keyTag() == tag) {
        zone.extraKeys.add(extra);
      }
      Assert.assertTrue("could not construct keys with same tag", k < 1000);
    }
    tree.build();
    assertTxtRejected(Reason.LIMIT_EXCEEDED);
  }

  @Test
  public void chainTooLong() throws Exception {
    TestTree t = new TestTree();
    t.addZone(".", DnssecCrypto.ED25519);
    String name = "";
    for (int i = 1; i <= DnssecValidator.MAX_ZONE_DEPTH; i++) {
      name = "l" + i + "." + name;
      t.addZone(name, DnssecCrypto.ED25519);
    }
    t.addData(name, "_acme-challenge." + name, TYPE_TXT, TestTree.txt("deep"));
    t.build();
    String deepName = "_acme-challenge." + name;
    assertReason(Reason.LIMIT_EXCEEDED,
        () -> new DnsClient(t, t.validator()).queryTxt(deepName));

    // one level less is accepted
    TestTree t2 = new TestTree();
    t2.addZone(".", DnssecCrypto.ED25519);
    name = "";
    for (int i = 1; i < DnssecValidator.MAX_ZONE_DEPTH; i++) {
      name = "l" + i + "." + name;
      t2.addZone(name, DnssecCrypto.ED25519);
    }
    t2.addData(name, "_acme-challenge." + name, TYPE_TXT, TestTree.txt("deep"));
    t2.build();
    Assert.assertEquals(Collections.singletonList("deep"),
        new DnsClient(t2, t2.validator()).queryTxt("_acme-challenge." + name));
  }

  @Test
  public void queryBudgetExhausted() throws Exception {
    List<DnsRecord> answer = tree.answer(ACME, TYPE_TXT);
    assertReason(Reason.LIMIT_EXCEEDED, () -> tree.validator().validate(ACME, TYPE_TXT,
        answer.subList(0, 1), answer.subList(1, 2), new ValidationBudget(2, 32, 30_000)));
  }

  @Test
  public void verificationBudgetExhausted() throws Exception {
    List<DnsRecord> answer = tree.answer(ACME, TYPE_TXT);
    assertReason(Reason.LIMIT_EXCEEDED, () -> tree.validator().validate(ACME, TYPE_TXT,
        answer.subList(0, 1), answer.subList(1, 2), new ValidationBudget(30, 2, 30_000)));
  }

  @Test
  public void deadlineExceeded() throws Exception {
    List<DnsRecord> answer = tree.answer(ACME, TYPE_TXT);
    assertReason(Reason.LIMIT_EXCEEDED, () -> tree.validator().validate(ACME, TYPE_TXT,
        answer.subList(0, 1), answer.subList(1, 2), new ValidationBudget(30, 32, -1)));
  }

  @Test
  public void deprecatedAlgorithms() throws Exception {
    for (int alg : new int[]{1, 3, 5, 6, 7, 12}) {
      resignTxt(sig -> sig.algorithm = alg);
      assertTxtRejected(Reason.UNSUPPORTED_ALGORITHM);
    }
  }

  @Test
  public void failureIsNotCached() throws Exception {
    DnssecValidator validator = tree.validator();
    DnsClient client = new DnsClient(tree, validator);

    List<DnsRecord> goodKeys = tree.answer(EXAMPLE, TYPE_DNSKEY);
    TestTree attacker = new TestTree("attacker");
    attacker.addZone(".", DnssecCrypto.ED25519);
    attacker.addZone("example.test.", DnssecCrypto.ED25519);
    attacker.build();
    tree.put(EXAMPLE, TYPE_DNSKEY, attacker.answer(EXAMPLE, TYPE_DNSKEY));
    assertReason(Reason.DS_MISMATCH, () -> client.queryTxt(ACME_NAME));

    tree.put(EXAMPLE, TYPE_DNSKEY, goodKeys);
    Assert.assertEquals(Collections.singletonList("token"), client.queryTxt(ACME_NAME));
  }

  @Test
  public void replaceTrustAnchors() throws Exception {
    DnssecValidator validator = tree.validator();
    DnsClient client = new DnsClient(tree, validator);
    Assert.assertEquals(Collections.singletonList("token"), client.queryTxt(ACME_NAME));

    // the validated keys are cached, but must not be used after the anchors are replaced
    TestTree other = new TestTree("other");
    other.addZone(".", DnssecCrypto.ED25519);
    validator.setTrustAnchors(other.trustAnchors());
    assertReason(Reason.DS_MISMATCH, () -> client.queryTxt(ACME_NAME));

    // old and new anchors together, as during a root KSK rollover
    List<DnsRecord> both = new ArrayList<>(other.trustAnchors());
    both.addAll(tree.trustAnchors());
    validator.setTrustAnchors(both);
    Assert.assertEquals(Collections.singletonList("token"), client.queryTxt(ACME_NAME));

    // invalid anchors are rejected, the current ones are kept
    try {
      validator.setTrustAnchors(Collections.emptyList());
      Assert.fail("expected IllegalArgumentException");
    } catch (IllegalArgumentException ex) {
      // expected
    }
    Assert.assertEquals(Collections.singletonList("token"), client.queryTxt(ACME_NAME));
  }

  @Test
  public void cnameLoop() throws Exception {
    tree.addData("example.test.", "a.example.test", TYPE_CNAME, TestTree.cname("b.example.test"));
    tree.addData("example.test.", "b.example.test", TYPE_CNAME, TestTree.cname("a.example.test"));
    tree.build();
    try {
      new DnsClient(tree, tree.validator()).queryTxt("a.example.test");
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("CNAME loop"));
    }
  }

  @Test
  public void unsignedAnswerAcceptedWithoutValidator() throws Exception {
    tree.put(ACME, TYPE_TXT, rrset(ACME, TYPE_TXT));
    Assert.assertEquals(Collections.singletonList("token"),
        new DnsClient(tree, null).queryTxt(ACME_NAME));
  }

}
