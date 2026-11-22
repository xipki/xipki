// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.misc.NameId;

/**
 * Unit test of {@link CaIdNameMap}.
 *
 * @author Lijun Liao (xipki)
 */
public class CaIdNameMapTest {

  @Test
  public void caLookupIsCaseInsensitive() {
    CaIdNameMap map = new CaIdNameMap();
    NameId ca = new NameId(1, "MyCA");
    map.addCa(ca);

    Assert.assertSame(ca, map.getCa(1));
    Assert.assertSame(ca, map.getCa("myca"));
    Assert.assertSame(ca, map.getCa("MYCA"));
    Assert.assertEquals("myca", map.getCaName(1));
    Assert.assertNull(map.getCaName(2));
    Assert.assertEquals(1, map.getAllCas().length);

    Assert.assertSame(ca, map.removeCa("MyCa"));
    Assert.assertNull(map.getCa(1));
    Assert.assertNull(map.getCa("myca"));
    Assert.assertNull(map.removeCa("myca"));
  }

  @Test
  public void certprofiles() {
    CaIdNameMap map = new CaIdNameMap();
    NameId tls = new NameId(1, "tls");
    NameId smime = new NameId(2, "smime");
    map.addCertprofile(tls);
    map.addCertprofile(smime);

    Assert.assertSame(tls, map.getCertprofile(1));
    Assert.assertSame(smime, map.getCertprofile("SMIME"));
    Assert.assertEquals("tls", map.getCertprofileName(1));
    Assert.assertEquals(2, map.getAllProfiles().length);

    Assert.assertSame(tls, map.removeCertprofile(1));
    Assert.assertNull(map.getCertprofile("tls"));
    Assert.assertNull(map.removeCertprofile(1));

    map.clearCertprofile();
    Assert.assertEquals(0, map.getAllProfiles().length);
    Assert.assertNull(map.getCertprofile(2));
  }

  @Test
  public void requestorsAndPublishers() {
    CaIdNameMap map = new CaIdNameMap();
    NameId requestor = new NameId(5, "ra");
    NameId publisher = new NameId(7, "ocsp-publisher");
    map.addRequestor(requestor);
    map.addPublisher(publisher);

    Assert.assertSame(requestor, map.getRequestor(5));
    Assert.assertSame(requestor, map.getRequestor("RA"));
    Assert.assertEquals(1, map.getAllRequestors().length);
    Assert.assertSame(publisher, map.getPublisher("OCSP-Publisher"));
    Assert.assertEquals("ocsp-publisher", map.getPublisherName(7));

    Assert.assertSame(requestor, map.removeRequestor(5));
    Assert.assertNull(map.getRequestor("ra"));
    Assert.assertSame(publisher, map.removePublisher(7));
    Assert.assertNull(map.getPublisher("ocsp-publisher"));
  }

  @Test
  public void replacingAnEntryWithTheSameName() {
    CaIdNameMap map = new CaIdNameMap();
    map.addCa(new NameId(1, "ca"));
    NameId replacement = new NameId(2, "ca");
    map.addCa(replacement);

    Assert.assertSame(replacement, map.getCa("ca"));
    Assert.assertEquals(1, map.getAllCas().length);
  }

  @Test
  public void clearAll() {
    CaIdNameMap map = new CaIdNameMap();
    map.addCa(new NameId(1, "ca"));
    map.addRequestor(new NameId(1, "ra"));
    map.addPublisher(new NameId(1, "pub"));

    map.clearCa();
    map.clearRequestor();
    map.clearPublisher();
    Assert.assertEquals(0, map.getAllCas().length);
    Assert.assertEquals(0, map.getAllRequestors().length);
    Assert.assertNull(map.getPublisherName(1));
  }

}
