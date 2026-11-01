// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Base64;
import org.xipki.codec.Hex;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;

/**
 * JUnit tests of {@link DnssecCrypto} and the signed data, with the examples of
 * RFC 5702 (RSA), RFC 6605 (ECDSA) and RFC 8080 (EdDSA).
 *
 * @author Lijun Liao (xipki)
 */
public class DnssecCryptoTest {

  private static final int TYPE_A = 1;

  private static final int TYPE_MX = 15;

  private static final byte[] A_192_0_2_1 = {(byte) 192, 0, 2, 1};

  private static final byte[] A_192_0_2_91 = {(byte) 192, 0, 2, 91};

  private static byte[] dnskey(int flags, int alg, String base64Key) {
    byte[] key = Base64.decode(base64Key);
    byte[] rdata = new byte[4 + key.length];
    rdata[0] = (byte) (flags >>> 8);
    rdata[1] = (byte) flags;
    rdata[2] = 3;
    rdata[3] = (byte) alg;
    System.arraycopy(key, 0, rdata, 4, key.length);
    return rdata;
  }

  private static long time(String yyyymmddhhmmss) {
    return LocalDateTime.parse(yyyymmddhhmmss, DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
        .toEpochSecond(ZoneOffset.UTC);
  }

  private static byte[] rrsig(int typeCovered, int alg, int labels, long ttl, long expiration,
                              long inception, int keyTag, String signer, String base64Sig) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write(out, typeCovered, 2);
    write(out, alg, 1);
    write(out, labels, 1);
    write(out, ttl, 4);
    write(out, expiration, 4);
    write(out, inception, 4);
    write(out, keyTag, 2);
    byte[] signerWire = DnsName.of(signer).toWire();
    out.write(signerWire, 0, signerWire.length);
    byte[] sig = Base64.decode(base64Sig);
    out.write(sig, 0, sig.length);
    return out.toByteArray();
  }

  private static void write(ByteArrayOutputStream out, long v, int len) {
    for (int i = len - 1; i >= 0; i--) {
      out.write((int) (v >>> (8 * i)));
    }
  }

  private static byte[] mxRdata() {
    byte[] name = DnsName.of("mail.example.com").toWire();
    byte[] rdata = new byte[2 + name.length];
    rdata[1] = 10;
    System.arraycopy(name, 0, rdata, 2, name.length);
    return rdata;
  }

  /**
   * Verifies the RRSIG over the RRset with one record, and that it fails after
   * modifying one byte of the data.
   */
  private static void assertVerifies(boolean expected, String owner, int type, byte[] rdata,
                                     byte[] dnskeyRdata, byte[] rrsigRdata) throws Exception {
    DnsName ownerName = DnsName.of(owner);
    DnssecValidator.Rrsig sig = new DnssecValidator.Rrsig(rrsigRdata);
    DnssecValidator.Dnskey key = new DnssecValidator.Dnskey(dnskeyRdata);
    Assert.assertEquals("key tag", sig.keyTag, key.keyTag);

    byte[] data = DnssecValidator.signedData(ownerName, type,
        Collections.singletonList(new DnsRecord(ownerName, type, DnsRecord.CLASS_IN, 3600,
            rdata)), sig);
    Assert.assertEquals(expected,
        DnssecCrypto.verify(sig.algorithm, key.publicKey, data, sig.signature));

    if (expected) {
      data[data.length - 1] ^= 1;
      Assert.assertFalse(DnssecCrypto.verify(sig.algorithm, key.publicKey, data,
          sig.signature));
    }
  }

  private static void assertDs(String owner, byte[] dnskeyRdata, int keyTag, int digestType,
                               String hexDigest) {
    Assert.assertEquals(keyTag, DnssecValidator.Dnskey.keyTag(dnskeyRdata));
    Assert.assertArrayEquals(Hex.decode(hexDigest),
        DnssecCrypto.dsDigest(digestType, DnsName.of(owner), dnskeyRdata));
  }

  // RFC 5702 section 6.1: the 512-bit key is shorter than the minimum of 1024 bits.
  @Test
  public void rsaSha256ShortKeyRejected() throws Exception {
    byte[] key = dnskey(256, 8, "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponcw"
        + "tkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=");
    byte[] sig = rrsig(TYPE_A, 8, 3, 3600, time("20300101000000"), time("20000101000000"),
        9033, "example.net", "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85m"
            + "wlMgNEacFYK/lPtPiVYP4bwg==");
    assertVerifies(false, "www.example.net", TYPE_A, A_192_0_2_91, key, sig);
  }

  // RFC 5702 section 6.2
  @Test
  public void rsaSha512() throws Exception {
    byte[] key = dnskey(256, 10, "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6p"
        + "nWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bW"
        + "XjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL");
    byte[] sig = rrsig(TYPE_A, 10, 3, 3600, time("20300101000000"), time("20000101000000"),
        3740, "example.net", "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0x"
            + "DtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvp"
            + "Xwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=");
    assertVerifies(true, "www.example.net", TYPE_A, A_192_0_2_91, key, sig);
  }

  // RFC 6605 section 6.1
  @Test
  public void ecdsaP256() throws Exception {
    byte[] key = dnskey(257, 13, "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7w"
        + "NcP+e+MAnLr+Wi9xMWyQLc8NAA==");
    assertDs("example.net", key, 55648, 2,
        "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17");
    byte[] sig = rrsig(TYPE_A, 13, 3, 3600, time("20100909100439"), time("20100812100439"),
        55648, "example.net", "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZo"
            + "LBLlUzGGus7ZwmwWep666VCw==");
    assertVerifies(true, "www.example.net", TYPE_A, A_192_0_2_1, key, sig);
  }

  // RFC 6605 section 6.2
  @Test
  public void ecdsaP384() throws Exception {
    byte[] key = dnskey(257, 14, "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhye"
        + "m5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40");
    assertDs("example.net", key, 10771, 4, "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9"
        + "495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6");
    byte[] sig = rrsig(TYPE_A, 14, 3, 3600, time("20100909102025"), time("20100812102025"),
        10771, "example.net", "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzF"
            + "axsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm");
    assertVerifies(true, "www.example.net", TYPE_A, A_192_0_2_1, key, sig);
  }

  // RFC 8080 section 6.1, corrected by erratum 4935 (labels 2, new signatures)
  @Test
  public void ed25519() throws Exception {
    byte[] key = dnskey(257, 15, "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    assertDs("example.com", key, 3613, 2,
        "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b");
    byte[] sig = rrsig(TYPE_MX, 15, 2, 3600, 1440021600, 1438207200, 3613, "example.com",
        "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==");
    assertVerifies(true, "example.com", TYPE_MX, mxRdata(), key, sig);

    key = dnskey(257, 15, "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=");
    assertDs("example.com", key, 35217, 2,
        "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c");
    sig = rrsig(TYPE_MX, 15, 2, 3600, 1440021600, 1438207200, 35217, "example.com",
        "zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==");
    assertVerifies(true, "example.com", TYPE_MX, mxRdata(), key, sig);
  }

  // RFC 8080 section 6.2, corrected by erratum 4935
  @Test
  public void ed448() throws Exception {
    byte[] key = dnskey(257, 16, "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1"
        + "FYYUcJKm1MDpJtIA");
    assertDs("example.com", key, 9713, 2,
        "6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7");
    byte[] sig = rrsig(TYPE_MX, 16, 2, 3600, 1440021600, 1438207200, 9713, "example.com",
        "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/N"
            + "BtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA");
    assertVerifies(true, "example.com", TYPE_MX, mxRdata(), key, sig);

    key = dnskey(257, 16, "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5Hl"
        + "HAMy12VoISsA");
    assertDs("example.com", key, 38353, 2,
        "645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba28af4");
    sig = rrsig(TYPE_MX, 16, 2, 3600, 1440021600, 1438207200, 38353, "example.com",
        "E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0AsQ4f7qI"
            + "1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA");
    assertVerifies(true, "example.com", TYPE_MX, mxRdata(), key, sig);
  }

  @Test
  public void invalidKeyEncodings() {
    byte[] data = {1, 2, 3};
    Assert.assertFalse(DnssecCrypto.verify(13, new byte[63], data, new byte[64]));
    Assert.assertFalse(DnssecCrypto.verify(13, new byte[64], data, new byte[63]));
    Assert.assertFalse(DnssecCrypto.verify(15, new byte[31], data, new byte[64]));
    Assert.assertFalse(DnssecCrypto.verify(8, new byte[2], data, new byte[256]));
    Assert.assertFalse(DnssecCrypto.verify(8, new byte[]{0, 0, 0, 1}, data, new byte[256]));
    Assert.assertFalse(DnssecCrypto.verify(5, new byte[260], data, new byte[256]));
  }

}
