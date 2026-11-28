// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.AccessDescription;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.CRLDistributionPoints;
import org.xipki.asn1.x509.ExtendedKeyUsage;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.pkix.ca.BadCertTemplateException;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.x509.id.ExtensionOIDs;
import org.xipki.codec.x509.id.KeyPurposeOIDs;
import org.xipki.codec.x509.id.X509OIDs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.ca.CaUris;
import org.xipki.pkix.ca.X509PublicCaInfo;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.misc.NameId;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The extensions of a certificate from the profile, the request and the CA
 * ({@link IdentifiedCertprofile#getExtensions}), and the subject check of
 * {@link CertprofileUtil#getSubject}.
 *
 * @author Lijun Liao (xipki)
 */
public class IdentifiedCertprofileTest {

  private static final X500Name CA_SUBJECT = new X500Name("CN=ca,O=myorg,C=DE");

  private static final byte[] CA_SKI = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  private static final CaUris CA_URIS = new CaUris(List.of("http://example.org/ca.der"),
      List.of("http://example.org/ocsp"), List.of("http://example.org/ca.crl"),
      List.of("http://example.org/ca-delta.crl"));

  private static final String SUBJECT =
      "{\"type\": \"country\", \"minOccurs\": 0},"
      + "{\"type\": \"organization\", \"minOccurs\": 0},"
      + "{\"type\": \"commonName\", \"toSAN\": \"DNSName\"}";

  /** Subject for profiles without the extension SubjectAlternativeName (no toSAN). */
  private static final String SUBJECT_NO_SAN = SUBJECT.replace(", \"toSAN\": \"DNSName\"", "");

  private static final String SKI = "{\"type\": \"SubjectKeyIdentifier\", \"required\": true}";

  private static final String AKI = "{\"type\": \"AuthorityKeyIdentifier\", \"required\": true}";

  private static final String AIA = "{\"type\": \"AuthorityInfoAccess\", \"required\": true,"
      + " \"authorityInfoAccess\": {\"includeCaIssuers\": true, \"includeOcsp\": true}}";

  private static final String CRLDP = "{\"type\": \"CRLDistributionPoints\"}";

  private static final String FRESHEST_CRL = "{\"type\": \"FreshestCRL\"}";

  private static final String BC = "{\"type\": \"BasicConstraints\", \"required\": true,"
      + " \"critical\": true}";

  private static final String KU = "{\"type\": \"KeyUsage\", \"required\": true,"
      + " \"critical\": true, \"inRequest\": \"optional\", \"keyUsage\": {\"usages\": [{"
      + "\"required\": [\"digitalSignature\"], \"optional\": [\"keyEncipherment\"]}]}}";

  private static final String EKU = "{\"type\": \"ExtendedKeyUsage\", \"required\": true,"
      + " \"inRequest\": \"optional\", \"extendedKeyUsage\": {"
      + "\"required\": [\"serverAuth\"], \"optional\": [\"clientAuth\"]}}";

  private static final String SAN = "{\"type\": \"SubjectAlternativeName\", \"required\": true,"
      + " \"inRequest\": \"optional\", \"subjectAltName\": {\"modes\": [\"DNSName\"]}}";

  private static final String EE_EXTENSIONS = String.join(",", SKI, AKI, AIA, CRLDP,
      FRESHEST_CRL, BC, KU, EKU, SAN);

  // ---------------------------------------------------------------- identifiers and URIs

  @Test
  public void keyIdentifiers() throws Exception {
    SubjectPublicKeyInfo key = key(KeySpec.P256);
    ExtensionValues values = extensions(eeProfile(), "CN=a.example.org", null, key);

    Assert.assertArrayEquals(HashAlgo.SHA1.hash(key.subjectPublicKey()),
        extn(values, ExtensionOIDs.subjectKeyIdentifier).getSubjectKeyIdentifier()
            .getKeyIdentifier());
    Assert.assertArrayEquals(CA_SKI,
        extn(values, ExtensionOIDs.authorityKeyIdentifier).getAuthorityKeyIdentifier()
            .keyIdentifier());
  }

  @Test
  public void urisOfTheCa() throws Exception {
    ExtensionValues values = extensions(eeProfile(), "CN=a.example.org", null, key(KeySpec.P256));

    List<AccessDescription> ads = extn(values, ExtensionOIDs.authorityInfoAccess)
        .getAuthorityInfoAccess().getEntries();
    Assert.assertEquals(2, ads.size());
    Assert.assertEquals(X509OIDs.id_ad_caIssuers, ads.get(0).getAccessMethod());
    Assert.assertEquals("http://example.org/ca.der",
        ads.get(0).getAccessLocation().getUri().getString());
    Assert.assertEquals(X509OIDs.id_ad_ocsp, ads.get(1).getAccessMethod());

    CRLDistributionPoints cdp = extn(values, ExtensionOIDs.cRLDistributionPoints)
        .getCRLDistributionPoints();
    Assert.assertEquals("http://example.org/ca.crl", cdp.get(0).getDistributionPoint()
        .getFullName().get(0).getUri().getString());
    Assert.assertNull("no indirect CRL", cdp.get(0).getCRLIssuer());

    CRLDistributionPoints freshest = extn(values, ExtensionOIDs.freshestCRL).getFreshestCRL();
    Assert.assertEquals("http://example.org/ca-delta.crl", freshest.get(0).getDistributionPoint()
        .getFullName().get(0).getUri().getString());
  }

  @Test
  public void aiaWithOcspOnly() throws Exception {
    String aia = AIA.replace("\"includeCaIssuers\": true", "\"includeCaIssuers\": false");
    ExtensionValues values = extensions(profile("EndEntity",
        String.join(",", SKI, aia, KU)), "CN=a.example.org", null, key(KeySpec.P256));
    List<AccessDescription> ads = extn(values, ExtensionOIDs.authorityInfoAccess)
        .getAuthorityInfoAccess().getEntries();
    Assert.assertEquals(1, ads.size());
    Assert.assertEquals(X509OIDs.id_ad_ocsp, ads.get(0).getAccessMethod());
  }

  @Test
  public void requiredAiaWithoutCaUris() throws Exception {
    IdentifiedCertprofile profile = profile("EndEntity", String.join(",", SKI, AIA, KU));
    X509PublicCaInfo caWithoutUris = new X509PublicCaInfo(CA_SUBJECT, CA_SUBJECT, BigInteger.ONE, null,
        CA_SKI, null, null);
    CertprofileException ex = Assert.assertThrows(CertprofileException.class,
        () -> profile.getExtensions(new X500Name("CN=a.example.org"),
            new X500Name("CN=a.example.org"), null, key(KeySpec.P256), caWithoutUris, null,
            Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS)));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("could not add required"));
  }

  // ---------------------------------------------------------------- basic constraints

  @Test
  public void basicConstraintsEndEntity() throws Exception {
    ExtensionValues values = extensions(eeProfile(), "CN=a.example.org", null, key(KeySpec.P256));
    ExtensionValue bc = values.getExtensionValue(ExtensionOIDs.basicConstraints);
    Assert.assertTrue("critical", bc.isCritical());
    Assert.assertFalse(extn(values, ExtensionOIDs.basicConstraints).getBasicConstraints().isCA());
  }

  @Test
  public void basicConstraintsRequestNotPermitted() throws Exception {
    // BasicConstraints without inRequest: the requested pathLen is ignored
    String ku = "{\"type\": \"KeyUsage\", \"required\": true, \"critical\": true,"
        + " \"keyUsage\": {\"usages\": [{\"required\": [\"keyCertSign\", \"cRLSign\"]}]}}";
    IdentifiedCertprofile profile = profile("SubCA", String.join(",", SKI,
        BC.replace("}", ", \"basicConstraints\": {\"pathLen\": 2}}"), ku));
    Assert.assertEquals(Integer.valueOf(2), pathLen(profile, new BasicConstraints(1)));
  }

  @Test
  public void basicConstraintsSubCa() throws Exception {
    IdentifiedCertprofile profile = subCaProfile(2);
    Assert.assertEquals(Integer.valueOf(2), pathLen(profile, null));
    // a smaller requested pathLen is used, a larger one not
    Assert.assertEquals(Integer.valueOf(1), pathLen(profile, new BasicConstraints(1)));
    Assert.assertEquals(Integer.valueOf(2), pathLen(profile, new BasicConstraints(5)));

    // a requested pathLen is used if the profile has none
    Assert.assertNull(pathLen(subCaProfile(null), null));
    Assert.assertEquals(Integer.valueOf(3), pathLen(subCaProfile(null), new BasicConstraints(3)));

    // an end entity request for a CA profile
    Assert.assertThrows(CertprofileException.class,
        () -> pathLen(profile, new BasicConstraints(false)));
  }

  // ---------------------------------------------------------------- key usage

  @Test
  public void keyUsageRequiredAndRequestedOptional() throws Exception {
    IdentifiedCertprofile profile = eeProfile();
    Assert.assertEquals(Set.of(KeyUsage.digitalSignature),
        keyUsages(extensions(profile, "CN=a.example.org", null, key(KeySpec.P256))));

    // an optional usage is set only if requested; a not configured one is ignored
    Extension requested = Extension.ofKeyUsage(true, new org.xipki.asn1.x509.KeyUsage(List.of(
        org.xipki.asn1.x509.KeyUsage.keyEncipherment, org.xipki.asn1.x509.KeyUsage.keyCertSign)));
    Assert.assertEquals(Set.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment),
        keyUsages(extensions(profile, "CN=a.example.org", new Extensions(requested),
            key(KeySpec.P256))));
  }

  @Test
  public void keyUsageFitsTheKeyType() throws Exception {
    // keyEncipherment is optional, it is removed for a signature-only key
    Extension requested = Extension.ofKeyUsage(true, new org.xipki.asn1.x509.KeyUsage(List.of(
        org.xipki.asn1.x509.KeyUsage.keyEncipherment)));
    Assert.assertEquals(Set.of(KeyUsage.digitalSignature),
        keyUsages(extensions(eeProfile(), "CN=a.example.org", new Extensions(requested),
            key(KeySpec.ED25519))));

    // a required usage which does not fit the key type
    IdentifiedCertprofile profile = profile("EndEntity", String.join(",", SKI,
        KU.replace("[\"digitalSignature\"]", "[\"digitalSignature\", \"keyAgreement\"]")));
    CertprofileException ex = Assert.assertThrows(CertprofileException.class,
        () -> extensions(profile, "CN=a.example.org", null, key(KeySpec.MLDSA44)));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("is not allowed for the key-spec"));
  }

  @Test
  public void keyUsageAndCertLevel() throws Exception {
    // keyCertSign in an end entity profile
    IdentifiedCertprofile ee = profile("EndEntity", String.join(",", SKI,
        KU.replace("[\"digitalSignature\"]", "[\"digitalSignature\", \"keyCertSign\"]")));
    Assert.assertThrows(CertprofileException.class,
        () -> extensions(ee, "CN=a.example.org", null, key(KeySpec.P256)));

    // a CA profile without keyCertSign and cRLSign
    IdentifiedCertprofile ca = profile("SubCA", String.join(",", SKI, BC, KU));
    Assert.assertThrows(CertprofileException.class,
        () -> extensions(ca, "CN=sub", null, key(KeySpec.P256)));
  }

  @Test
  public void cabForumCaRequiresCrlSign() throws Exception {
    String ku = "{\"type\": \"KeyUsage\", \"required\": true, \"critical\": true,"
        + " \"keyUsage\": {\"usages\": [{\"required\": [\"keyCertSign\"]}]}}";
    String extensions = String.join(",", SKI, BC, ku);
    String subject = "{\"type\": \"country\"}, {\"type\": \"organization\"},"
        + " {\"type\": \"commonName\"}";
    IdentifiedCertprofile profile = new IdentifiedCertprofile(
        new CertprofileEntry(new NameId(1, "test"), "xijson",
            json("SubCA", extensions, ",\"certDomain\": \"CABForumBR\"", subject)),
        xijson("SubCA", extensions, ",\"certDomain\": \"CABForumBR\"", subject));
    CertprofileException ex = Assert.assertThrows(CertprofileException.class,
        () -> extensions(profile, "CN=sub,O=myorg,C=DE", null, key(KeySpec.P256)));
    Assert.assertEquals("CA profile does not contain keyUsage cRLSign", ex.getMessage());
  }

  // ---------------------------------------------------------------- extended key usage

  @Test
  public void extendedKeyUsage() throws Exception {
    IdentifiedCertprofile profile = eeProfile();
    ExtendedKeyUsage eku = extn(extensions(profile, "CN=a.example.org", null, key(KeySpec.P256)),
        ExtensionOIDs.extendedKeyUsage).getExtendedKeyUsage();
    Assert.assertTrue(eku.hasKeyPurposeId(KeyPurposeOIDs.id_kp_serverAuth));
    Assert.assertFalse(eku.hasKeyPurposeId(KeyPurposeOIDs.id_kp_clientAuth));

    // optional clientAuth is set if requested, codeSigning is not configured
    Extension requested = Extension.ofExtendedKeyUsage(false, new ExtendedKeyUsage(List.of(
        KeyPurposeOIDs.id_kp_clientAuth, KeyPurposeOIDs.id_kp_codeSigning)));
    eku = extn(extensions(profile, "CN=a.example.org", new Extensions(requested),
        key(KeySpec.P256)), ExtensionOIDs.extendedKeyUsage).getExtendedKeyUsage();
    Assert.assertTrue(eku.hasKeyPurposeId(KeyPurposeOIDs.id_kp_serverAuth));
    Assert.assertTrue(eku.hasKeyPurposeId(KeyPurposeOIDs.id_kp_clientAuth));
    Assert.assertFalse(eku.hasKeyPurposeId(KeyPurposeOIDs.id_kp_codeSigning));
  }

  // ---------------------------------------------------------------- subject alternative name

  @Test
  public void sanFromCommonName() throws Exception {
    GeneralNames san = extn(extensions(eeProfile(), "CN=a.example.org", null, key(KeySpec.P256)),
        ExtensionOIDs.subjectAlternativeName).getSubjectAlternativeName();
    Assert.assertTrue(san.getEntries().contains(GeneralName.ofDnsName("a.example.org")));
  }

  @Test
  public void sanFromRequest() throws Exception {
    Extension requested = Extension.ofSubjectAlternativeName(false, new GeneralNames(
        GeneralName.ofDnsName("b.example.org")));
    GeneralNames san = extn(extensions(eeProfile(), "CN=a.example.org",
        new Extensions(requested), key(KeySpec.P256)), ExtensionOIDs.subjectAlternativeName)
        .getSubjectAlternativeName();
    Assert.assertTrue(san.getEntries().contains(GeneralName.ofDnsName("a.example.org")));
    Assert.assertTrue(san.getEntries().contains(GeneralName.ofDnsName("b.example.org")));
  }

  @Test
  public void sanModeNotAllowed() throws Exception {
    Extension requested = Extension.ofSubjectAlternativeName(false, new GeneralNames(
        GeneralName.ofRfc822Name("a@example.org")));
    Assert.assertThrows(BadCertTemplateException.class, () -> extensions(eeProfile(),
        "CN=a.example.org", new Extensions(requested), key(KeySpec.P256)));
  }

  // ---------------------------------------------------------------- requested extensions

  @Test
  public void requestedExtensionsNotInProfileAreIgnored() throws Exception {
    Extension unknown = Extension.createNoParse(new Asn1Oid("1.2.3.4.9"), false,
        new org.xipki.codec.asn1.Asn1Utf8String("x"));
    ExtensionValues values = extensions(eeProfile(), "CN=a.example.org",
        new Extensions(unknown), key(KeySpec.P256));
    Assert.assertNull(values.getExtensionValue(new Asn1Oid("1.2.3.4.9")));
  }

  @Test
  public void requestedExtensionNotPermittedInRequestIsIgnored() throws Exception {
    // SubjectAlternativeName without inRequest: the requested name is not used
    IdentifiedCertprofile profile = profile("EndEntity", String.join(",", SKI, KU,
        SAN.replace(" \"inRequest\": \"optional\",", "")));
    Extension requested = Extension.ofSubjectAlternativeName(false, new GeneralNames(
        GeneralName.ofDnsName("b.example.org")));
    GeneralNames san = extn(extensions(profile, "CN=a.example.org", new Extensions(requested),
        key(KeySpec.P256)), ExtensionOIDs.subjectAlternativeName).getSubjectAlternativeName();
    Assert.assertFalse(san.getEntries().contains(GeneralName.ofDnsName("b.example.org")));
  }

  @Test
  public void constantExtension() throws Exception {
    String constant = "{\"type\": \"1.2.3.4.5.3\", \"required\": true, \"critical\": true,"
        + " \"constant\": {\"type\": \"UTF8\", \"value\": \"my UTF8 string\"}}";
    ExtensionValues values = extensions(profile("EndEntity", String.join(",", SKI, KU, constant)),
        "CN=a.example.org", null, key(KeySpec.P256));
    ExtensionValue value = values.getExtensionValue(new Asn1Oid("1.2.3.4.5.3"));
    Assert.assertNotNull(value);
    Assert.assertTrue(value.isCritical());
    Assert.assertEquals(new org.xipki.codec.asn1.Asn1Utf8String("my UTF8 string")
        .toAsn1Primitive(), value.value());
  }

  // ---------------------------------------------------------------- subject (CertprofileUtil)

  @Test
  public void invalidCountryCode() throws Exception {
    BadCertTemplateException ex = Assert.assertThrows(BadCertTemplateException.class,
        () -> CertprofileUtil.getSubject(xijson("EndEntity", SKI),
            new X500Name("CN=a.example.org,C=XX")));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("invalid country/area code"));
  }

  @Test
  public void cabForumEndEntitySubject() throws Exception {
    XijsonCertprofile profile = xijson("EndEntity", SKI, ",\"certDomain\": \"CABForumBR\"",
        "{\"type\": \"country\", \"minOccurs\": 0},"
            + "{\"type\": \"organization\", \"minOccurs\": 0},"
            + "{\"type\": \"locality\", \"minOccurs\": 0},"
            + "{\"type\": \"commonName\"}");
    CertprofileUtil.getSubject(profile, new X500Name("CN=a.example.org"));
    CertprofileUtil.getSubject(profile, new X500Name("CN=a.example.org,L=Berlin,O=myorg,C=DE"));

    // organization requires the country
    Assert.assertThrows(BadCertTemplateException.class, () -> CertprofileUtil.getSubject(
        profile, new X500Name("CN=a.example.org,L=Berlin,O=myorg")));
    // locality is prohibited without organization (or given name / surname)
    Assert.assertThrows(BadCertTemplateException.class, () -> CertprofileUtil.getSubject(
        profile, new X500Name("CN=a.example.org,L=Berlin")));
  }

  @Test
  public void cabForumCaSubjectRequiresOrganizationAndCountry() throws Exception {
    XijsonCertprofile profile = xijson("SubCA", SKI, ",\"certDomain\": \"CABForumBR\"",
        "{\"type\": \"country\", \"minOccurs\": 0},"
            + "{\"type\": \"organization\", \"minOccurs\": 0},"
            + "{\"type\": \"commonName\"}");
    CertprofileUtil.getSubject(profile, new X500Name("CN=sub,O=myorg,C=DE"));
    Assert.assertThrows(BadCertTemplateException.class,
        () -> CertprofileUtil.getSubject(profile, new X500Name("CN=sub,C=DE")));
    Assert.assertThrows(BadCertTemplateException.class,
        () -> CertprofileUtil.getSubject(profile, new X500Name("CN=sub,O=myorg")));
  }

  // ---------------------------------------------------------------- helpers

  private static IdentifiedCertprofile eeProfile() throws CertprofileException {
    return profile("EndEntity", EE_EXTENSIONS);
  }

  private static IdentifiedCertprofile subCaProfile(Integer pathLen) throws CertprofileException {
    // the requested BasicConstraints are only used if permitted in the request
    String bcInRequest = BC.replace("}", ", \"inRequest\": \"optional\"}");
    String bc = (pathLen == null) ? bcInRequest
        : bcInRequest.replace("}", ", \"basicConstraints\": {\"pathLen\": " + pathLen + "}}");
    String ku = "{\"type\": \"KeyUsage\", \"required\": true, \"critical\": true,"
        + " \"keyUsage\": {\"usages\": [{\"required\": [\"keyCertSign\", \"cRLSign\"]}]}}";
    return profile("SubCA", String.join(",", SKI, bc, ku));
  }

  private static IdentifiedCertprofile profile(String certLevel, String extensions)
      throws CertprofileException {
    return new IdentifiedCertprofile(new CertprofileEntry(new NameId(1, "test"), "xijson",
        json(certLevel, extensions, "", subjectFor(extensions))), xijson(certLevel, extensions));
  }

  private static XijsonCertprofile xijson(String certLevel, String extensions)
      throws CertprofileException {
    return xijson(certLevel, extensions, "", subjectFor(extensions));
  }

  private static String subjectFor(String extensions) {
    return extensions.contains("SubjectAlternativeName") ? SUBJECT : SUBJECT_NO_SAN;
  }

  private static XijsonCertprofile xijson(String certLevel, String extensions, String topLevel,
                                          String subject) throws CertprofileException {
    XijsonCertprofile profile = new XijsonCertprofile();
    profile.initialize(json(certLevel, extensions, topLevel, subject));
    return profile;
  }

  private static String json(String certLevel, String extensions, String topLevel,
                             String subject) {
    return "{\"certLevel\": \"" + certLevel + "\", \"validity\": \"1y\","
        + " \"notBeforeTime\": \"current\"" + topLevel + ", \"subject\": [" + subject + "],"
        + " \"extensions\": [" + extensions + "]}";
  }

  private static X509PublicCaInfo caInfo() {
    return new X509PublicCaInfo(CA_SUBJECT, CA_SUBJECT, BigInteger.ONE, null, CA_SKI, CA_URIS, null);
  }

  private static ExtensionValues extensions(IdentifiedCertprofile profile, String subject,
                                            Extensions requested, SubjectPublicKeyInfo key)
      throws Exception {
    X500Name requestedSubject = new X500Name(subject);
    X500Name grantedSubject = CertprofileUtil.getSubject(profile.certprofile(),
        requestedSubject).grantedSubject();
    Instant notBefore = Instant.now();
    return profile.getExtensions(requestedSubject, grantedSubject, requested, key, caInfo(),
        null, notBefore, notBefore.plus(30, ChronoUnit.DAYS));
  }

  private static Extension extn(ExtensionValues values, Asn1Oid type) throws Exception {
    ExtensionValue value = values.getExtensionValue(type);
    Assert.assertNotNull("extension " + type.getId(), value);
    return Extension.create(type, value.isCritical(), value.value());
  }

  private static Integer pathLen(IdentifiedCertprofile profile, BasicConstraints requested)
      throws Exception {
    Extensions req = (requested == null) ? null
        : new Extensions(Extension.ofBasicConstraints(true, requested));
    BasicConstraints bc = extn(extensions(profile, "CN=sub", req, key(KeySpec.P256)),
        ExtensionOIDs.basicConstraints).getBasicConstraints();
    Assert.assertTrue(bc.isCA());
    return bc.pathLenConstraint();
  }

  private static Set<KeyUsage> keyUsages(ExtensionValues values) throws Exception {
    org.xipki.asn1.x509.KeyUsage ku = extn(values, ExtensionOIDs.keyUsage).getKeyUsage();
    Set<KeyUsage> ret = new HashSet<>();
    for (KeyUsage usage : KeyUsage.values()) {
      if (ku.hasFlag(usage.asn1())) {
        ret.add(usage);
      }
    }
    return ret;
  }

  private static SubjectPublicKeyInfo key(KeySpec spec) {
    try {
      return KeyUtil.generateX509KeyPair2(spec).subjectPublicKeyInfo();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

}
