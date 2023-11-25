// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.JSON;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * JUnit test case of encoding and decoding json messages.
 * @author Lijun Liao (xipki)
 */
public class JsonEnDecodeTest {

  @Test
  public void jsonEncodeDecode() {
    AcmeIdentifier id = new AcmeIdentifier("id0", "value0");
    AcmeChallenge ch1 = new AcmeChallenge("http-01", 1, "my-token",
        "my-expected-authz", ChallengeStatus.pending);
    ch1.setValidated(now());
    AcmeAuthz authz1 = new AcmeAuthz(1, id);
    authz1.setStatus(AuthzStatus.valid);
    authz1.setExpires(now().plus(1, ChronoUnit.DAYS));
    authz1.setChallenges(List.of(ch1));

    String encAuthz1 = JSON.toJson(authz1.encode());
    System.out.println("encoded authz1: " + encAuthz1);

    Map<String, Object> dMap = JSON.parseObject(encAuthz1, Map.class);
    AcmeAuthz authz2 = AcmeAuthz.decode(dMap);

    Assert.assertTrue("AcmeAuthz", authz1.equals(authz2));

    String encAuthz2 = JSON.toJson(authz2.encode());
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
