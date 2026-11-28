// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x500.RDN;
import org.xipki.asn1.x500.X500Name;
import org.xipki.pkix.ca.BadCertTemplateException;
import org.xipki.pkix.ca.CertLevel;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.ctrl.KeypairGenControl;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.Validity;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Behavior of {@link XijsonCertprofile}, each test with a small profile.
 *
 * @author Lijun Liao (xipki)
 */
public class XijsonCertprofileTest {

  private static final String SUBJECT =
      "{\"type\": \"country\", \"minOccurs\": 0},"
      + "{\"type\": \"organization\", \"minOccurs\": 0},"
      + "{\"type\": \"organizationalUnit\", \"minOccurs\": 0, \"maxOccurs\": 2},"
      + "{\"type\": \"commonName\", \"regex\": \":FQDN\"}";

  private static final String EXTENSIONS =
      "{\"type\": \"SubjectKeyIdentifier\", \"required\": true}";

  // ---------------------------------------------------------------- subject

  @Test
  public void subjectIsGrantedInProfileOrder() throws Exception {
    XijsonCertprofile profile = profile("");
    X500Name granted = subject(profile, "CN=a.example.org,O=myorg,C=DE");
    Assert.assertEquals(X509Util.canonicalizeName(new X500Name("C=DE,O=myorg,CN=a.example.org")),
        X509Util.canonicalizeName(granted));
    Assert.assertEquals(X500Name.C, granted.getRDNs().get(0).getFirst().getType());
    Assert.assertEquals(X500Name.CN, granted.getRDNs().get(2).getFirst().getType());
  }

  @Test
  public void requiredRdnMissing() throws Exception {
    assertBadSubject(profile(""), "O=myorg,C=DE", "required subject DN");
  }

  @Test
  public void rdnTypeNotInProfile() throws Exception {
    assertBadSubject(profile(""), "CN=a.example.org,L=Berlin", "is not allowed");
  }

  @Test
  public void rdnOccurrence() throws Exception {
    XijsonCertprofile profile = profile("");
    X500Name granted = subject(profile, "CN=a.example.org,OU=ou2,OU=ou1,O=myorg");
    Assert.assertEquals(2, granted.getRDNs(X500Name.OU).size());

    assertBadSubject(profile, "CN=a.example.org,OU=ou3,OU=ou2,OU=ou1", "not within the allowed range");
  }

  @Test
  public void rdnRegex() throws Exception {
    XijsonCertprofile profile = profile("");
    subject(profile, "CN=a.example.org");
    assertBadSubject(profile, "CN=not a domain", "against regex");
  }

  @Test
  public void rdnValueIsTrimmed() throws Exception {
    X500Name granted = subject(profile(""), "CN=a.example.org,O=  myorg  ");
    Assert.assertEquals("myorg", X509Util.rdnValueToString(
        granted.getRDNs(X500Name.O).get(0).getFirst().getValue()));
  }

  @Test
  public void fixedRdnValue() throws Exception {
    XijsonCertprofile profile = profile(build("",
        "{\"type\": \"organization\", \"value\": \"fixed org\"},"
            + "{\"type\": \"commonName\"}", EXTENSIONS));
    X500Name granted = subject(profile, "CN=a.example.org");
    Assert.assertEquals("fixed org", X509Util.rdnValueToString(
        granted.getRDNs(X500Name.O).get(0).getFirst().getValue()));

    // a fixed value may not be requested
    assertBadSubject(profile, "CN=a.example.org,O=other", "not allowed in the request");
  }

  @Test
  public void printableString() throws Exception {
    XijsonCertprofile profile = profile(build("",
        "{\"type\": \"organization\", \"printableString\": true},"
            + "{\"type\": \"commonName\"}", EXTENSIONS));
    subject(profile, "CN=a,O=my org");
    assertBadSubject(profile, "CN=a,O=my@org", "non-printableString");
  }

  @Test
  public void crossCertKeepsTheRequestedSubject() throws Exception {
    XijsonCertprofile profile = profile(build("", SUBJECT, EXTENSIONS)
        .replace("\"certLevel\": \"EndEntity\"", "\"certLevel\": \"CROSS\""));
    X500Name requested = new X500Name("CN=a.example.org,O=myorg,C=DE");
    Assert.assertEquals(CertLevel.CROSS, profile.certLevel());
    Assert.assertSame(requested, profile.subject(requested).grantedSubject());
  }

  @Test
  public void tooLongRdnValue() throws Exception {
    // the upper bound of commonName is 64
    // built from the RDN, the parser of X500Name rejects the too long text already
    X500Name requested = new X500Name(new RDN(X500Name.CN, new Asn1Utf8String("a".repeat(65))));
    XijsonCertprofile profile = profile(build("", "{\"type\": \"commonName\"}", EXTENSIONS));
    BadCertTemplateException ex = Assert.assertThrows(BadCertTemplateException.class,
        () -> profile.subject(requested));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("too long"));
    // the message names the RDN type, not the value twice
    Assert.assertFalse(ex.getMessage(), ex.getMessage().startsWith("subject " + "a".repeat(65)));
  }

  @Test
  public void toSanRequiresSubjectAltName() throws Exception {
    String subject = "{\"type\": \"commonName\", \"toSAN\": \"DNSName\"}";
    CertprofileException ex = Assert.assertThrows(CertprofileException.class,
        () -> profile(build("", subject, EXTENSIONS)));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("subjectAltName is not permitted"));

    // SubjectAltName without configured modes: all modes are allowed
    profile(build("", subject, EXTENSIONS + ",{\"type\": \"SubjectAlternativeName\"}"));

    // the mode of toSAN is not among the configured ones
    Assert.assertThrows(CertprofileException.class, () -> profile(build("", subject, EXTENSIONS
        + ",{\"type\": \"SubjectAlternativeName\", \"subjectAltName\": "
        + "{\"modes\": [\"IPAddress\"]}}")));
  }

  // ---------------------------------------------------------------- validity and time

  @Test
  public void validity() throws Exception {
    XijsonCertprofile profile = profile("");
    Assert.assertEquals(Validity.getInstance("1y"), profile.validity());
    Assert.assertFalse(profile.hasNoWellDefinedExpirationDate());
  }

  @Test
  public void undefinedValidity() throws Exception {
    for (String v : new String[]{"UNDEFINED", "99991231235959Z"}) {
      XijsonCertprofile profile = profile(build("", SUBJECT, EXTENSIONS)
          .replace("\"validity\": \"1y\"", "\"validity\": \"" + v + "\""));
      Assert.assertTrue(v, profile.hasNoWellDefinedExpirationDate());
      Assert.assertNull(v, profile.validity());
    }
  }

  @Test
  public void notBeforeCurrent() throws Exception {
    Instant before = Instant.now();
    Instant notBefore = notBeforeProfile("current").notBefore(null);
    assertBetween(notBefore, before, Instant.now());
  }

  @Test
  public void notBeforeWithOffset() throws Exception {
    Instant before = Instant.now();
    Instant notBefore = notBeforeProfile("+1h").notBefore(null);
    assertBetween(notBefore, before.plus(1, ChronoUnit.HOURS),
        Instant.now().plus(1, ChronoUnit.HOURS));

    before = Instant.now();
    notBefore = notBeforeProfile("-5m").notBefore(null);
    assertBetween(notBefore, before.minus(5, ChronoUnit.MINUTES),
        Instant.now().minus(5, ChronoUnit.MINUTES));
  }

  @Test
  public void notBeforeMidnight() throws Exception {
    ZoneId zone = ZoneId.of("GMT+2");
    Instant notBefore = notBeforeProfile("midnight:GMT+2").notBefore(null);
    ZonedDateTime zdt = notBefore.atZone(zone);
    Assert.assertEquals(0, zdt.getHour());
    Assert.assertEquals(0, zdt.getMinute());
    Assert.assertEquals(0, zdt.getSecond());
    // the next midnight
    Assert.assertTrue(notBefore.isAfter(Instant.now().minusSeconds(1)));
    Assert.assertTrue(notBefore.isBefore(Instant.now().plus(1, ChronoUnit.DAYS)));
  }

  @Test
  public void requestedNotBeforeInThePastIsNotUsed() throws Exception {
    Instant before = Instant.now();
    Instant notBefore = notBeforeProfile("current").notBefore(before.minus(1, ChronoUnit.DAYS));
    assertBetween(notBefore, before, Instant.now());
  }

  @Test
  public void requestedNotBeforeInTheFutureIsUsed() throws Exception {
    Instant requested = Instant.now().plus(2, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
    Assert.assertEquals(requested, notBeforeProfile("current").notBefore(requested));
  }

  @Test
  public void invalidNotBefore() {
    for (String v : new String[]{"midnight:GMT+13", "abc", "1x", "-11m"}) {
      Assert.assertThrows(v, CertprofileException.class, () -> notBeforeProfile(v));
    }
  }

  // ---------------------------------------------------------------- public key

  @Test
  public void keyAlgorithms() throws Exception {
    XijsonCertprofile profile = profile(",\"keyAlgorithms\": [\"P256\", \"ED25519\"]");
    profile.checkPublicKey(publicKey(KeySpec.P256));
    profile.checkPublicKey(publicKey(KeySpec.ED25519));
    assertBadKey(profile, publicKey(KeySpec.P384));
    assertBadKey(profile, publicKey(KeySpec.RSA2048));
  }

  @Test
  public void allKeyAlgorithmsWithoutRestriction() throws Exception {
    XijsonCertprofile profile = profile("");
    for (KeySpec spec : new KeySpec[]{KeySpec.P256, KeySpec.RSA2048, KeySpec.ED448,
        KeySpec.MLDSA44, KeySpec.MLKEM768}) {
      profile.checkPublicKey(publicKey(spec));
    }
  }

  @Test
  public void unknownKeyAlgorithm() throws Exception {
    SubjectPublicKeyInfo unknown = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(new org.xipki.codec.asn1.Asn1Oid("1.2.3.4.5")), new byte[32]);
    assertBadKey(profile(""), unknown);
  }

  @Test
  public void keyUsagePerKeyType() throws Exception {
    String keyUsage = "{\"type\": \"KeyUsage\", \"required\": true, \"keyUsage\": {\"usages\": ["
        + "{\"appliesTo\": [\"MLDSA44\"], \"required\": [\"digitalSignature\"]},"
        + "{\"appliesTo\": [\"MLKEM768\"], \"required\": [\"keyEncipherment\"]},"
        + "{\"required\": [\"digitalSignature\"], \"optional\": [\"keyAgreement\"]}]}}";
    XijsonCertprofile profile = profile(build("", SUBJECT, EXTENSIONS + "," + keyUsage));

    Assert.assertEquals(Set.of("digitalSignature+"), usages(profile.keyUsage(KeySpec.MLDSA44)));
    Assert.assertEquals(Set.of("keyEncipherment+"), usages(profile.keyUsage(KeySpec.MLKEM768)));
    // default for the other key types
    Assert.assertEquals(Set.of("digitalSignature+", "keyAgreement"),
        usages(profile.keyUsage(KeySpec.P256)));
  }

  // ---------------------------------------------------------------- keypair generation

  @Test
  public void keypairGeneration() throws Exception {
    Assert.assertTrue(profile("").keypairGenControl().isForbidden());

    KeypairGenControl kg = profile(",\"keypairGeneration\": \"P384\"").keypairGenControl();
    Assert.assertFalse(kg.isForbidden());
    Assert.assertEquals(KeySpec.P384, kg.keySpec());

    Assert.assertTrue(profile(",\"keypairGeneration\": \"InheritCA\"").keypairGenControl()
        .isInheritCA());
    Assert.assertTrue(profile(",\"keypairGeneration\": \"Forbidden\"").keypairGenControl()
        .isForbidden());
  }

  // ---------------------------------------------------------------- others

  @Test
  public void signatureAlgorithms() throws Exception {
    Assert.assertNull(profile("").signatureAlgorithms());
    List<SignAlgo> algos = profile(",\"signatureAlgorithms\": "
        + "[\"SHA256withECDSA\", \"Ed25519\", \"SHA256withECDSA\"]").signatureAlgorithms();
    // duplicates are removed
    Assert.assertEquals(Set.of(SignAlgo.ofName("SHA256withECDSA"), SignAlgo.ofName("Ed25519")),
        new HashSet<>(algos));
    Assert.assertEquals(2, algos.size());
  }

  @Test
  public void signatureAlgorithmsKeepTheConfiguredOrder() throws Exception {
    for (String[] names : new String[][]{{"SHA256withECDSA", "Ed25519", "SHA256withRSA"},
        {"SHA256withRSA", "Ed25519", "SHA256withECDSA"}}) {
      List<SignAlgo> algos = profile(",\"signatureAlgorithms\": [\"" + String.join("\", \"", names)
          + "\"]").signatureAlgorithms();
      Assert.assertEquals(List.of(SignAlgo.ofName(names[0]), SignAlgo.ofName(names[1]),
          SignAlgo.ofName(names[2])), algos);
    }
  }

  @Test
  public void maxSize() throws Exception {
    Assert.assertEquals(4000, profile(",\"maxSize\": 4000").maxCertSize());
  }

  @Test
  public void invalidProfiles() {
    // no certLevel
    assertInvalid(build("", SUBJECT, EXTENSIONS).replace("\"certLevel\": \"EndEntity\",", ""));
    // unknown extension without configuration
    assertInvalid(build("", SUBJECT, "{\"type\": \"1.2.3.4.1\", \"required\": true}"));
    // unknown key algorithm
    assertInvalid(build(",\"keyAlgorithms\": [\"NoSuchKey\"]", SUBJECT, EXTENSIONS));
    // minOccurs > maxOccurs
    assertInvalid(build("", "{\"type\": \"commonName\", \"minOccurs\": 2, \"maxOccurs\": 1}",
        EXTENSIONS));
    // not JSON
    assertInvalid("not json");
  }

  // ---------------------------------------------------------------- helpers

  static String build(String topLevel, String subject, String extensions) {
    return "{\"certLevel\": \"EndEntity\", \"validity\": \"1y\", \"notBeforeTime\": \"current\""
        + topLevel + ", \"subject\": [" + subject + "], \"extensions\": [" + extensions + "]}";
  }

  private static XijsonCertprofile profile(String topLevelOrJson) throws CertprofileException {
    String json = topLevelOrJson.startsWith("{") ? topLevelOrJson
        : build(topLevelOrJson, SUBJECT, EXTENSIONS);
    XijsonCertprofile profile = new XijsonCertprofile();
    profile.initialize(json);
    return profile;
  }

  private static XijsonCertprofile notBeforeProfile(String notBefore)
      throws CertprofileException {
    return profile(build("", SUBJECT, EXTENSIONS).replace(
        "\"notBeforeTime\": \"current\"", "\"notBeforeTime\": \"" + notBefore + "\""));
  }

  private static X500Name subject(XijsonCertprofile profile, String requested)
      throws BadCertTemplateException {
    SubjectInfo info = profile.subject(new X500Name(requested));
    return info.grantedSubject();
  }

  private static void assertBadSubject(XijsonCertprofile profile, String requested,
                                       String expectedMessagePart) {
    BadCertTemplateException ex = Assert.assertThrows(BadCertTemplateException.class,
        () -> profile.subject(new X500Name(requested)));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains(expectedMessagePart));
  }

  private static void assertBadKey(XijsonCertprofile profile, SubjectPublicKeyInfo key) {
    Assert.assertThrows(BadCertTemplateException.class, () -> profile.checkPublicKey(key));
  }

  private static void assertInvalid(String json) {
    Assert.assertThrows(json, CertprofileException.class, () -> profile(json));
  }

  private static void assertBetween(Instant value, Instant min, Instant max) {
    // Instant.now() of the profile may be some ms after min and before max
    Assert.assertFalse(value + " < " + min, value.isBefore(min.minus(Duration.ofSeconds(1))));
    Assert.assertFalse(value + " > " + max, value.isAfter(max.plus(Duration.ofSeconds(1))));
  }

  private static SubjectPublicKeyInfo publicKey(KeySpec spec) throws Exception {
    return KeyUtil.generateX509KeyPair2(spec).subjectPublicKeyInfo();
  }

  /** Key usages as text, required ones with the suffix '+'. */
  private static Set<String> usages(Set<KeySingleUsage> usages) {
    Set<String> ret = new HashSet<>();
    for (KeySingleUsage u : usages) {
      ret.add(u.keyUsage().getName() + (u.isRequired() ? "+" : ""));
    }
    return ret;
  }

}
