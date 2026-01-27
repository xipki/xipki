// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge2 implements JsonEncodable {

  private final AcmeChallenge challenge;

  private final AcmeIdentifier identifier;

  public AcmeChallenge2(AcmeChallenge challenge, AcmeIdentifier identifier) {
    this.challenge = Args.notNull(challenge, "challenge");
    this.identifier = Args.notNull(identifier, "identifier");
  }

  public AcmeChallenge getChallenge() {
    return challenge;
  }

  public AcmeIdentifier getIdentifier() {
    return identifier;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("challenge", challenge)
        .put("identifier", identifier);
  }

  public static AcmeChallenge2 parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("challenge");
    AcmeChallenge challenge = (map == null) ? null : AcmeChallenge.parse(map);

    map = json.getMap("identifier");
    AcmeIdentifier identifier = (map == null) ? null
        : AcmeIdentifier.parse(map);
    return new AcmeChallenge2(challenge, identifier);
  }

}
