// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x500.RDN;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.AccessDescription;
import org.xipki.asn1.x509.AuthorityInfoAccessSyntax;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.CRLDistributionPoints;
import org.xipki.asn1.x509.DistributionPoint;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.pkix.ca.CertLevel;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.codec.Base64;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.util.ConfPairs;
import org.xipki.codec.x509.id.X509OIDs;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.FileOrValue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Unit test of {@link CaUtil}.
 *
 * @author Lijun Liao (xipki)
 */
public class CaUtilTest {

  @Test
  public void basicConstraints() {
    Assert.assertFalse(CaUtil.createBasicConstraints(CertLevel.EndEntity, 3).isCA());

    BasicConstraints bc = CaUtil.createBasicConstraints(CertLevel.SubCA, 2);
    Assert.assertTrue(bc.isCA());
    Assert.assertEquals(2, bc.pathLenConstraint().intValue());

    bc = CaUtil.createBasicConstraints(CertLevel.RootCA, null);
    Assert.assertTrue(bc.isCA());
    Assert.assertNull(bc.pathLenConstraint());
  }

  @Test
  public void authorityInformationAccess() {
    AuthorityInfoAccessSyntax aia = CaUtil.createAuthorityInformationAccess(
        List.of("http://example.org/ca.der"),
        List.of("http://example.org/ocsp1", "http://example.org/ocsp2"));
    List<AccessDescription> ads = aia.getEntries();
    Assert.assertEquals(3, ads.size());
    Assert.assertEquals(X509OIDs.id_ad_caIssuers, ads.get(0).getAccessMethod());
    Assert.assertEquals(X509OIDs.id_ad_ocsp, ads.get(1).getAccessMethod());
    Assert.assertEquals(X509OIDs.id_ad_ocsp, ads.get(2).getAccessMethod());

    // only OCSP
    Assert.assertEquals(1, CaUtil.createAuthorityInformationAccess(
        null, List.of("http://example.org/ocsp")).size());

    Assert.assertThrows(IllegalArgumentException.class,
        () -> CaUtil.createAuthorityInformationAccess(null, List.of()));
  }

  @Test
  public void crlDistributionPoints() {
    X500Name caSubject = new X500Name("CN=ca,C=DE");
    List<String> uris = List.of("http://example.org/1.crl", "http://example.org/2.crl");

    DistributionPoint dp = single(CaUtil.createCrlDistributionPoints(uris, caSubject, null));
    Assert.assertEquals(2, dp.getDistributionPoint().getFullName().size());
    Assert.assertNull(dp.getCRLIssuer());

    // the CRL signer is the CA itself: no cRLIssuer
    Assert.assertNull(single(CaUtil.createCrlDistributionPoints(
        uris, caSubject, new X500Name("CN=ca,C=DE"))).getCRLIssuer());

    // indirect CRL
    DistributionPoint indirect = single(CaUtil.createCrlDistributionPoints(
        uris, caSubject, new X500Name("CN=crlsigner,C=DE")));
    Assert.assertNotNull(indirect.getCRLIssuer());

    Assert.assertThrows(IllegalArgumentException.class,
        () -> CaUtil.createCrlDistributionPoints(List.of(), caSubject, null));
  }

  @Test
  public void sortNameFollowsTheForwardOrder() {
    X500Name sorted = CaUtil.sortName(new X500Name("CN=cn,OU=ou,O=o,C=DE"));
    List<Asn1Oid> forward = SubjectDnSpec.getForwardDNs();

    List<RDN> rdns = sorted.getRDNs();
    Assert.assertEquals(4, rdns.size());
    for (int i = 1; i < rdns.size(); i++) {
      int prev = forward.indexOf(rdns.get(i - 1).getFirst().getType());
      int curr = forward.indexOf(rdns.get(i).getFirst().getType());
      Assert.assertTrue("RDN order at index " + i, prev < curr);
    }

    // sorting is idempotent
    Assert.assertEquals(sorted, CaUtil.sortName(sorted));
  }

  @Test
  public void sortNameKeepsMultipleRdnsOfSameType() {
    X500Name sorted = CaUtil.sortName(new X500Name("CN=cn,OU=ou2,OU=ou1,C=DE"));
    List<RDN> ous = sorted.getRDNs(X500Name.OU);
    Assert.assertEquals(2, ous.size());
    Assert.assertEquals(4, sorted.size());
  }

  @Test
  public void removeEmptyRdns() {
    X500Name name = new X500Name("CN=cn,C=DE");
    // nothing to remove: the same instance is returned
    Assert.assertSame(name, CaUtil.removeEmptyRdns(name));

    X500Name withEmpty = new X500Name(new RDN(X500Name.C, new Asn1Utf8String("DE")),
        new RDN(X500Name.OU, new Asn1Utf8String("")),
        new RDN(X500Name.CN, new Asn1Utf8String("cn")));
    X500Name cleaned = CaUtil.removeEmptyRdns(withEmpty);
    Assert.assertEquals(2, cleaned.size());
    Assert.assertTrue(cleaned.getRDNs(X500Name.OU).isEmpty());
  }

  @Test
  public void canonicalizeSignerConfWithoutKeystoreIsUnchanged() throws Exception {
    String conf = "algo=SHA256withECDSA,slot=0,key-label=ca1";
    Assert.assertSame(conf, CaUtil.canonicalizeSignerConf(conf, "."));
  }

  @Test
  public void canonicalizeSignerConfInlinesKeystoreFile() throws Exception {
    Path dir = Files.createTempDirectory("xipki-cautil-test");
    byte[] keystore = "dummy keystore".getBytes(StandardCharsets.UTF_8);
    Files.write(dir.resolve("ca.p12"), keystore);

    String conf = CaUtil.canonicalizeSignerConf(
        "algo=SHA256withECDSA,password=CHANGEIT,keystore=file:ca.p12", dir.toString());
    ConfPairs pairs = new ConfPairs(conf);
    Assert.assertEquals("base64:" + Base64.encodeToString(keystore), pairs.value("keystore"));
    Assert.assertEquals("CHANGEIT", pairs.value("password"));
    Assert.assertEquals(SignAlgo.ofName("SHA256withECDSA").jceName(), pairs.value("algo"));

    // already inlined: stays the same
    Assert.assertEquals(conf, CaUtil.canonicalizeSignerConf(conf, dir.toString()));

    // non-existing file
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.canonicalizeSignerConf(
        "password=CHANGEIT,keystore=file:missing.p12", dir.toString()));
  }

  @Test
  public void canonicalizeSignerConfRejectsUnknownAlgo() {
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.canonicalizeSignerConf(
        "algo=NoSuchAlgo,keystore=base64:AAAA", "."));
  }

  @Test
  public void fileOrValue() throws Exception {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    String longContent = "x".repeat(256);
    try (ZipOutputStream zip = new ZipOutputStream(bout)) {
      Assert.assertNull(CaUtil.createFileOrValue(zip, null, "a.txt"));
      Assert.assertNull(CaUtil.createFileOrValue(zip, "", "a.txt"));

      FileOrValue small = CaUtil.createFileOrValue(zip, "short", "small.txt");
      Assert.assertEquals("short", small.value());
      Assert.assertNull(small.file());

      FileOrValue large = CaUtil.createFileOrValue(zip, longContent, "large.txt");
      Assert.assertNull(large.value());
      Assert.assertEquals("large.txt", large.file());
    }

    Assert.assertEquals(List.of("large.txt"), zipEntryNames(bout.toByteArray()));
    Assert.assertEquals(longContent, new String(
        zipEntry(bout.toByteArray(), "large.txt"), StandardCharsets.UTF_8));
  }

  @Test
  public void fileOrBinary() throws Exception {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    byte[] smallBytes = new byte[255];
    byte[] largeBytes = new byte[256];
    Arrays.fill(largeBytes, (byte) 7);
    try (ZipOutputStream zip = new ZipOutputStream(bout)) {
      Assert.assertNull(CaUtil.createFileOrBinary(zip, null, "a.bin"));
      Assert.assertNull(CaUtil.createFileOrBinary(zip, new byte[0], "a.bin"));
      Assert.assertNull(CaUtil.createFileOrBase64Value(zip, "", "a.bin"));

      FileOrBinary small = CaUtil.createFileOrBinary(zip, smallBytes, "small.bin");
      Assert.assertArrayEquals(smallBytes, small.binary());
      Assert.assertNull(small.file());

      FileOrBinary large = CaUtil.createFileOrBase64Value(zip,
          Base64.encodeToString(largeBytes), "large.bin");
      Assert.assertNull(large.binary());
      Assert.assertEquals("large.bin", large.file());
    }

    Assert.assertEquals(List.of("large.bin"), zipEntryNames(bout.toByteArray()));
    Assert.assertArrayEquals(largeBytes, zipEntry(bout.toByteArray(), "large.bin"));
  }

  @Test
  public void permissions() {
    Assert.assertEquals(List.of(PermissionConstants.getTextForCode(PermissionConstants.ALL)),
        CaUtil.getPermissions(PermissionConstants.ALL));

    List<String> list = CaUtil.getPermissions(
        PermissionConstants.ENROLL_CERT | PermissionConstants.REVOKE_CERT);
    Assert.assertEquals(2, list.size());
    Assert.assertTrue(list.contains(
        PermissionConstants.getTextForCode(PermissionConstants.ENROLL_CERT)));
    Assert.assertTrue(list.contains(
        PermissionConstants.getTextForCode(PermissionConstants.REVOKE_CERT)));

    Assert.assertTrue(CaUtil.getPermissions(0).isEmpty());
  }

  @Test
  public void asModifiableList() {
    List<String> list = CaUtil.asModifiableList("a", "b");
    list.add("c");
    Assert.assertEquals(List.of("a", "b", "c"), list);
  }

  @Test
  public void parseInvalidCert() {
    // input shorter than the PEM header "-----BEGIN"
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.parseCert(new byte[0]));
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.parseCert(new byte[]{1, 2, 3}));
    Assert.assertThrows(CaMgmtException.class,
        () -> CaUtil.parseCert("-----BEG".getBytes(StandardCharsets.US_ASCII)));
    Assert.assertThrows(CaMgmtException.class,
        () -> CaUtil.parseCert("AAAA".getBytes(StandardCharsets.US_ASCII)));
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.parseCert(new byte[32]));
    Assert.assertThrows(CaMgmtException.class, () -> CaUtil.parseCert(
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".getBytes(StandardCharsets.US_ASCII)));
  }

  private static DistributionPoint single(CRLDistributionPoints cdp) {
    Assert.assertEquals(1, cdp.size());
    return cdp.get(0);
  }

  private static List<String> zipEntryNames(byte[] zipBytes) throws Exception {
    List<String> names = new ArrayList<>();
    try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        names.add(entry.getName());
      }
    }
    return names;
  }

  private static byte[] zipEntry(byte[] zipBytes, String name) throws Exception {
    try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        if (entry.getName().equals(name)) {
          return zip.readAllBytes();
        }
      }
    }
    throw new AssertionError("ZIP entry " + name + " not found");
  }

}
