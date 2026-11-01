// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.codec.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.List;

/**
 * JUnit tests of {@link TrustAnchorsFile}: parsing and reloading.
 *
 * @author Lijun Liao (xipki)
 */
public class TrustAnchorsFileTest {

  private static final String DS_2017 = ". 172800 IN DS 20326 8 2 "
      + "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n";

  private static final String DS_2024 = ". 172800 IN DS 38696 8 2 "
      + "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n";

  private Path file;

  @Before
  public void createFile() throws IOException {
    file = Files.createTempFile("root-anchors", ".zone");
  }

  @After
  public void deleteFile() throws IOException {
    Files.deleteIfExists(file);
  }

  private void write(String text, long modifiedSeconds) throws IOException {
    Files.write(file, text.getBytes(StandardCharsets.UTF_8));
    Files.setLastModifiedTime(file, FileTime.fromMillis(modifiedSeconds * 1000));
  }

  @Test
  public void reloadOnlyWhenChanged() throws Exception {
    write(DS_2017, 1000);
    TrustAnchorsFile anchorsFile = new TrustAnchorsFile(file);
    Assert.assertEquals(1, anchorsFile.load().size());
    Assert.assertNull("unchanged file", anchorsFile.loadIfChanged());

    // new modification time
    write(DS_2017 + DS_2024, 2000);
    List<DnsRecord> anchors = anchorsFile.loadIfChanged();
    Assert.assertNotNull(anchors);
    Assert.assertEquals(2, anchors.size());
    Assert.assertNull(anchorsFile.loadIfChanged());

    // same modification time, other size
    write(DS_2024, 2000);
    anchors = anchorsFile.loadIfChanged();
    Assert.assertNotNull(anchors);
    Assert.assertEquals(1, anchors.size());
  }

  @Test
  public void invalidFileReportedOnce() throws Exception {
    write(DS_2017, 1000);
    TrustAnchorsFile anchorsFile = new TrustAnchorsFile(file);
    anchorsFile.load();

    write("# no anchors\n", 2000);
    try {
      anchorsFile.loadIfChanged();
      Assert.fail("expected IOException");
    } catch (IOException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("no trust anchors"));
    }
    // reported once, until the file changes again
    Assert.assertNull(anchorsFile.loadIfChanged());

    write(". IN DS 1 8 2 XYZ\n", 3000);
    try {
      anchorsFile.loadIfChanged();
      Assert.fail("expected IOException");
    } catch (IOException ex) {
      // expected
    }

    write(DS_2024, 4000);
    Assert.assertEquals(1, anchorsFile.loadIfChanged().size());
  }

  @Test
  public void missingFile() throws Exception {
    write(DS_2017, 1000);
    TrustAnchorsFile anchorsFile = new TrustAnchorsFile(file);
    anchorsFile.load();
    Files.delete(file);
    try {
      anchorsFile.loadIfChanged();
      Assert.fail("expected IOException");
    } catch (IOException ex) {
      // expected
    }
  }

  private static List<DnsRecord> parse(String text) throws IOException {
    return TrustAnchorsFile.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void rootAnchorsFile() throws Exception {
    // as shipped in xipki-gateway/tomcat/xipki/etc/acme/root-trust-anchors.zone
    String text = "# DNS Root Trust Anchors\n#\n# Format:\n\n"
        + ". 172800 IN DS 20326 8 2 "
        + "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
        + ". 172800 IN DS 38696 8 2 "
        + "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n";
    List<DnsRecord> anchors = parse(text);
    Assert.assertEquals(2, anchors.size());

    DnsRecord ds = anchors.get(0);
    Assert.assertEquals(DnsName.ROOT, ds.name());
    Assert.assertEquals(DnsRecord.TYPE_DS, ds.type());
    Assert.assertEquals(172800, ds.ttl());
    // DS RDATA: key tag 20326, algorithm 8, digest type 2, digest
    Assert.assertArrayEquals(Hex.decode("4F660802"
        + "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"), ds.rdata());
  }

  @Test
  public void dnskeyWithParenthesesAndComments() throws Exception {
    String text = "; root KSK\n"
        + ".  IN  DNSKEY  257 3 15 ( ; Ed25519\n"
        + "    l02Woi0iS8Aa25FQkUd9RMzZ\n"
        + "    HJpBoRQwAQEX1SxZJA4= )\n"
        + "example.com DS 3613 15 2 (3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79\n"
        + "    a304b)\n";
    List<DnsRecord> anchors = parse(text);
    Assert.assertEquals(2, anchors.size());

    DnssecValidator.Dnskey key = new DnssecValidator.Dnskey(anchors.get(0).rdata());
    Assert.assertEquals(257, key.flags);
    Assert.assertEquals(15, key.algorithm);
    Assert.assertEquals(3613, key.keyTag);

    DnsRecord ds = anchors.get(1);
    Assert.assertEquals(DnsName.of("example.com"), ds.name());
    byte[] digest = Arrays.copyOfRange(ds.rdata(), 4, ds.rdata().length);
    Assert.assertArrayEquals(DnssecCrypto.dsDigest(2, ds.name(), anchors.get(0).rdata()),
        digest);
  }

  @Test
  public void invalidAnchors() {
    String[] invalid = {
        ". IN A 192.0.2.1\n",
        ". IN DS 20326 8\n",
        ". IN DS 70000 8 2 E06D\n",
        ". IN DS 20326 8 2 XYZ\n",
        ". IN DNSKEY 257 3 15 (abc\n",
        ". IN DNSKEY 257 3 15 abc)\n",
        "\n"
    };
    for (String text : invalid) {
      try {
        List<DnsRecord> anchors = parse(text);
        Assert.assertTrue("accepted " + text, text.trim().isEmpty() && anchors.isEmpty());
      } catch (IOException ex) {
        // expected
      }
    }
  }

}
