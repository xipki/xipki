// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JUnit tests of {@link DnsClient} without DNSSEC: address lookup and CNAMEs.
 *
 * @author Lijun Liao (xipki)
 */
public class DnsClientTest {

  /** Answers from a map; a missing entry gives NOERROR without answer. */
  private static final class MapTransport implements DnsTransport {

    private final Map<String, List<DnsRecord>> answers = new HashMap<>();

    private final Map<String, Integer> rcodes = new HashMap<>();

    void put(String name, int type, byte[]... rdatas) {
      List<DnsRecord> records = new ArrayList<>();
      for (byte[] rdata : rdatas) {
        records.add(new DnsRecord(DnsName.of(name), type, DnsRecord.CLASS_IN, 60, rdata));
      }
      answers.put(DnsName.of(name) + "/" + type, records);
    }

    @Override
    public DnsMessage query(DnsName qname, int qtype) throws IOException {
      String key = qname + "/" + qtype;
      Integer rcode = rcodes.get(key);
      if (rcode != null && rcode < 0) {
        throw new IOException("timeout");
      }

      List<DnsRecord> answer = answers.get(key);
      if (answer == null) {
        answer = answers.get(qname + "/" + DnsRecord.TYPE_CNAME);
      }
      return new DnsMessage(0, DnsMessage.FLAG_QR,
          rcode == null ? DnsMessage.RCODE_NOERROR : rcode, qname, qtype,
          answer == null ? Collections.emptyList() : answer,
          Collections.emptyList(), Collections.emptyList());
    }

  }

  private static byte[] ip(String literal) throws IOException {
    return InetAddress.getByName(literal).getAddress();
  }

  @Test
  public void addresses() throws Exception {
    MapTransport t = new MapTransport();
    t.put("www.example.org", DnsRecord.TYPE_A, ip("192.0.2.1"), ip("192.0.2.2"));
    t.put("www.example.org", DnsRecord.TYPE_AAAA, ip("2001:db8::1"));
    List<InetAddress> addrs = new DnsClient(t, null).queryAddresses("www.example.org");
    Assert.assertEquals(Arrays.asList(InetAddress.getByName("192.0.2.1"),
        InetAddress.getByName("192.0.2.2"), InetAddress.getByName("2001:db8::1")), addrs);
    Assert.assertEquals("www.example.org", addrs.get(0).getHostName());
  }

  @Test
  public void addressesViaCname() throws Exception {
    MapTransport t = new MapTransport();
    t.put("www.example.org", DnsRecord.TYPE_CNAME, DnsName.of("cdn.example.net").toWire());
    t.put("cdn.example.net", DnsRecord.TYPE_A, ip("198.51.100.7"));
    Assert.assertEquals(Collections.singletonList(InetAddress.getByName("198.51.100.7")),
        new DnsClient(t, null).queryAddresses("www.example.org"));
  }

  @Test
  public void oneQueryFails() throws Exception {
    MapTransport t = new MapTransport();
    t.put("www.example.org", DnsRecord.TYPE_A, ip("192.0.2.1"));
    t.rcodes.put(DnsName.of("www.example.org") + "/" + DnsRecord.TYPE_AAAA,
        DnsMessage.RCODE_SERVFAIL);
    Assert.assertEquals(Collections.singletonList(InetAddress.getByName("192.0.2.1")),
        new DnsClient(t, null).queryAddresses("www.example.org"));

    // both fail: the error is thrown
    t.rcodes.put(DnsName.of("www.example.org") + "/" + DnsRecord.TYPE_A, -1);
    try {
      new DnsClient(t, null).queryAddresses("www.example.org");
      Assert.fail("expected IOException");
    } catch (IOException ex) {
      // expected
    }
  }

  @Test
  public void noAddress() throws Exception {
    MapTransport t = new MapTransport();
    t.rcodes.put(DnsName.of("none.example.org") + "/" + DnsRecord.TYPE_A,
        DnsMessage.RCODE_NXDOMAIN);
    t.rcodes.put(DnsName.of("none.example.org") + "/" + DnsRecord.TYPE_AAAA,
        DnsMessage.RCODE_NXDOMAIN);
    Assert.assertTrue(new DnsClient(t, null).queryAddresses("none.example.org").isEmpty());
  }

  @Test
  public void wrongAddressLength() throws Exception {
    MapTransport t = new MapTransport();
    // A record with an IPv6 address
    t.put("www.example.org", DnsRecord.TYPE_A, ip("2001:db8::1"));
    try {
      new DnsClient(t, null).queryAddresses("www.example.org");
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("invalid RDATA length"));
    }
  }

  @Test
  public void txtIgnoresOtherOwners() throws Exception {
    MapTransport t = new MapTransport();
    t.answers.put(DnsName.of("_acme-challenge.example.org") + "/" + DnsRecord.TYPE_TXT,
        Collections.singletonList(new DnsRecord(DnsName.of("evil.example.org"),
            DnsRecord.TYPE_TXT, DnsRecord.CLASS_IN, 60, new byte[]{1, 'x'})));
    Assert.assertTrue(new DnsClient(t, null).queryTxt("_acme-challenge.example.org").isEmpty());
  }

}
