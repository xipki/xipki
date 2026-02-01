// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.codec.ipadress.IPAddress;
import org.xipki.util.codec.ipadress.IPAddressFamily;

/**
 * @author Lijun Liao (xipki)
 */
public class IPAddressTest {

  @Test
  public void executeTest() {
    int afi = IPAddressFamily.AFI_IPv4;
    IPAddress.Context context = IPAddress.Context.PREFIX;
    IPAddress addr = IPAddress.getIPv4Instance("10.0.0.1", context);
    Assert.assertEquals("10.0.0.1", "10.0.0.1/32",
        addr.toString(afi, context));

    addr = IPAddress.getIPv4Instance("10.0.1/24", context);
    Assert.assertEquals("10.0.1/24", "10.0.1/24",
        addr.toString(afi, context));

    context = IPAddress.Context.RANGE_MIN;
    addr = IPAddress.getIPv4Instance("10.2.0.0", context);

    Assert.assertEquals("10.2.0.0", "10.2.0.0",
        addr.toString(afi, context));

    // 10.4.255.255
    context = IPAddress.Context.RANGE_MAX;
    addr = IPAddress.getIPv4Instance("10.4.255.255", context);
    Assert.assertEquals("10.4.255.255", "10.4.255.255",
        addr.toString(afi, context));

    // 2002:1::/64
    afi = IPAddressFamily.AFI_IPv6;
    context = IPAddress.Context.PREFIX;
    addr = IPAddress.getIPv6Instance("2002:1::/64", context);
    Assert.assertEquals("2002:1::/64", "2002:1::/64",
        addr.toString(afi, context));

    addr = IPAddress.getIPv6Instance("2002:2::/56", context);
    Assert.assertEquals("2002:2::/56", "2002:2::/56",
        addr.toString(afi, context));

    context = IPAddress.Context.RANGE_MIN;
    addr = IPAddress.getIPv6Instance("2002:3::", context);
    Assert.assertEquals("2002:3::", "2002:3::",
        addr.toString(afi, context));

    context = IPAddress.Context.RANGE_MAX;
    addr = IPAddress.getIPv6Instance("2002:8::fff:ffff:ffff:ffff:ffff",
        context);
    Assert.assertEquals("2002:8::fff:ffff:ffff:ffff:ffff",
        "2002:8:0:fff:ffff:ffff:ffff:ffff",
        addr.toString(afi, context));
  }

}
