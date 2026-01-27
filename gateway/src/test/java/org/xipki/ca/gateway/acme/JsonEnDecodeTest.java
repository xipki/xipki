// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;

/**
 * JUnit test case of encoding and decoding json messages.
 * @author Lijun Liao (xipki)
 */
public class JsonEnDecodeTest {

  @Test
  public void jsonEncodeDecode() throws CodecException {
    AcmeIdentifier id = new AcmeIdentifier("id0", "value0");
    AcmeChallenge ch1 = new AcmeChallenge("http-01", 1, "my-token",
        "my-expected-authz", ChallengeStatus.pending);
    ch1.setValidated(now());
    AcmeAuthz authz1 = new AcmeAuthz(1, id);
    authz1.setStatus(AuthzStatus.valid);
    authz1.setExpires(now().plus(1, ChronoUnit.DAYS));
    authz1.setChallenges(List.of(ch1));

    String encAuthz1 = JsonBuilder.toJson(authz1.toCodec());
    System.out.println("encoded authz1: " + encAuthz1);

    JsonMap dMap = JsonParser.parseMap(encAuthz1, false);
    AcmeAuthz authz2 = AcmeAuthz.parse(dMap);

    Assert.assertEquals("AcmeAuthz", authz1, authz2);

    String encAuthz2 = JsonBuilder.toJson(authz2.toCodec());
    System.out.println("encoded authz2: " + encAuthz2);

    Assert.assertEquals("encoded AcmeAuthz", encAuthz1, encAuthz2);

    AcmeAuthz authz3 = new AcmeAuthz(3, id);
    AcmeChallenge ch3 = new AcmeChallenge("http-03", 3, "my-token3",
        "my-expected-authz3", ChallengeStatus.pending);
    ch3.setValidated(now().plus(Integer.MAX_VALUE, ChronoUnit.SECONDS));
    authz3.setStatus(AuthzStatus.pending);
    authz3.setExpires(now().plus(Integer.MAX_VALUE, ChronoUnit.SECONDS));
    authz3.setChallenges(List.of(ch3));

    List<AcmeAuthz> authzs1 = Arrays.asList(authz1, authz3);
    String encAuthzs1 = AcmeAuthz.encodeAuthzs(authzs1);
    System.out.println("encoded authzs1: " + encAuthzs1);
    List<AcmeAuthz> authzs2 = AcmeAuthz.decodeAuthzs(encAuthzs1);
    Assert.assertTrue("List<AcmeAuthz>", authzs1.equals(authzs2));
    String encAuthzs2 = AcmeAuthz.encodeAuthzs(authzs2);
    System.out.println("encoded authzs2: " + encAuthzs2);
    Assert.assertEquals("encoded AcmeAuthzs", encAuthzs1, encAuthzs2);
  }

  private static Instant now() {
      return Instant.now().truncatedTo(ChronoUnit.SECONDS);
  }
}
