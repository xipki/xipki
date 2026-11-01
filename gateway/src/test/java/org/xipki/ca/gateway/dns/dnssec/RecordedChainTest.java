// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.ca.gateway.dns.DnsClient;
import org.xipki.ca.gateway.dns.DnsException;
import org.xipki.ca.gateway.dns.DnsMessage;
import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.ca.gateway.dns.DnsTransport;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates a chain of trust recorded from the Internet (root, org., ietf.org.) at the
 * time of the recording, with the root trust anchors shipped with the gateway. This
 * guards against errors that the synthetic signer and the validator share.
 *
 * @author Lijun Liao (xipki)
 */
public class RecordedChainTest {

  // content of xipki-gateway/tomcat/xipki/etc/acme/root-trust-anchors.zone
  private static final String ROOT_ANCHORS =
      ". 172800 IN DS 20326 8 2 "
      + "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
      + ". 172800 IN DS 38696 8 2 "
      + "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n";

  private final Map<String, byte[]> responses = new HashMap<>();

  private long recordedAt;

  private final DnsTransport transport = (qname, qtype) -> {
    byte[] raw = responses.get(qname + "/" + qtype);
    if (raw == null) {
      throw new IOException("no recorded response for " + qname + "/" + qtype);
    }
    return DnsMessage.parse(raw);
  };

  @Before
  public void loadChain() throws IOException {
    try (InputStream in = getClass().getResourceAsStream("/dnssec/ietf.org-chain.txt")) {
      BufferedReader reader = new BufferedReader(
          new InputStreamReader(in, StandardCharsets.US_ASCII));
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("# epoch seconds at capture:")) {
          recordedAt = Long.parseLong(line.substring(line.indexOf(':') + 1).trim());
        } else if (!line.startsWith("#") && !line.trim().isEmpty()) {
          String[] tokens = line.split(" ");
          responses.put(DnsName.of(tokens[0]) + "/" + tokens[1], Hex.decode(tokens[2]));
        }
      }
    }
  }

  private DnssecValidator validator(long epochSeconds) throws IOException {
    List<DnsRecord> anchors = TrustAnchorsFile.parse(
        new ByteArrayInputStream(ROOT_ANCHORS.getBytes(StandardCharsets.US_ASCII)));
    TestTree.MutableClock clock = new TestTree.MutableClock();
    clock.millis = epochSeconds * 1000;
    return new DnssecValidator(transport, anchors, clock);
  }

  @Test
  public void validAtRecordingTime() throws Exception {
    List<String> txts = new DnsClient(transport, validator(recordedAt)).queryTxt("ietf.org");
    Assert.assertFalse(txts.isEmpty());
    boolean spf = false;
    for (String txt : txts) {
      spf |= txt.startsWith("v=spf1");
    }
    Assert.assertTrue("SPF record expected in " + txts, spf);
  }

  @Test
  public void expiredLongAfterRecording() throws Exception {
    // the signatures are valid for days to weeks, so they are expired after a year
    try {
      new DnsClient(transport, validator(recordedAt + 365L * 86400)).queryTxt("ietf.org");
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertEquals(ex.getMessage(), DnsException.Reason.SIGNATURE_EXPIRED,
          ex.reason());
    }
  }

  @Test
  public void modifiedRecordedTxtRejected() throws Exception {
    // flip one byte in the last TXT RDATA byte of the first answer record
    byte[] raw = responses.get("ietf.org./16");
    DnsMessage m = DnsMessage.parse(raw);
    String firstTxt = m.answer().get(0).txt();
    byte[] needle = firstTxt.substring(firstTxt.length() - 4).getBytes(StandardCharsets.US_ASCII);
    int idx = indexOf(raw, needle);
    Assert.assertTrue(idx > 0);
    raw = raw.clone();
    raw[idx] ^= 0x01;
    responses.put("ietf.org./16", raw);

    try {
      new DnsClient(transport, validator(recordedAt)).queryTxt("ietf.org");
      Assert.fail("expected DnsException");
    } catch (DnsException ex) {
      Assert.assertEquals(ex.getMessage(), DnsException.Reason.INVALID_SIGNATURE,
          ex.reason());
    }
  }

  private static int indexOf(byte[] data, byte[] needle) {
    outer:
    for (int i = 0; i <= data.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (data[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

}
