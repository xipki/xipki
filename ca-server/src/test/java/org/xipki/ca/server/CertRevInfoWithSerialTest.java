// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkix.cert.CrlReason;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Unit test of {@link CertRevInfoWithSerial}.
 *
 * @author Lijun Liao (xipki)
 */
public class CertRevInfoWithSerialTest {

  private static final Instant REV_TIME = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  public void reasonCodeConstructor() {
    Instant invalidity = REV_TIME.minusSeconds(3600);
    CertRevInfoWithSerial info = new CertRevInfoWithSerial(10, BigInteger.TEN,
        CrlReason.KEY_COMPROMISE.code(), REV_TIME, invalidity);
    Assert.assertEquals(10, info.id());
    Assert.assertEquals(BigInteger.TEN, info.serial());
    Assert.assertEquals(CrlReason.KEY_COMPROMISE, info.reason());
    Assert.assertEquals(REV_TIME, info.revocationTime());
    Assert.assertEquals(invalidity, info.invalidityTime());
  }

  @Test
  public void serialZeroIsAccepted() {
    // serial 0 is allowed (e.g. in an indirect CRL)
    CertRevInfoWithSerial info = new CertRevInfoWithSerial(1, BigInteger.ZERO,
        CrlReason.UNSPECIFIED, REV_TIME, null);
    Assert.assertEquals(BigInteger.ZERO, info.serial());
    Assert.assertNull(info.invalidityTime());
  }

  @Test
  public void mandatoryFields() {
    Assert.assertThrows(RuntimeException.class, () -> new CertRevInfoWithSerial(
        1, null, CrlReason.UNSPECIFIED, REV_TIME, null));
    Assert.assertThrows(RuntimeException.class, () -> new CertRevInfoWithSerial(
        1, BigInteger.ONE, (CrlReason) null, REV_TIME, null));
    Assert.assertThrows(RuntimeException.class, () -> new CertRevInfoWithSerial(
        1, BigInteger.ONE, CrlReason.UNSPECIFIED, null, null));
  }

  @Test
  public void sortedBySerial() {
    List<CertRevInfoWithSerial> list = new ArrayList<>();
    list.add(info(1, 300));
    list.add(info(2, 5));
    list.add(info(3, 42));
    Collections.sort(list);
    Assert.assertEquals(BigInteger.valueOf(5), list.get(0).serial());
    Assert.assertEquals(BigInteger.valueOf(42), list.get(1).serial());
    Assert.assertEquals(BigInteger.valueOf(300), list.get(2).serial());
  }

  @Test
  public void equalityUsesIdAndSerial() {
    CertRevInfoWithSerial a = info(1, 7);
    CertRevInfoWithSerial b = new CertRevInfoWithSerial(1, BigInteger.valueOf(7),
        CrlReason.CA_COMPROMISE, REV_TIME.plusSeconds(1), null);
    Assert.assertEquals(a, b);
    Assert.assertEquals(a.hashCode(), b.hashCode());

    Assert.assertNotEquals(a, info(2, 7));
    Assert.assertNotEquals(a, info(1, 8));
    Assert.assertNotEquals(a, "not a CertRevInfoWithSerial");
  }

  private static CertRevInfoWithSerial info(long id, long serial) {
    return new CertRevInfoWithSerial(id, BigInteger.valueOf(serial),
        CrlReason.KEY_COMPROMISE, REV_TIME, null);
  }

}
