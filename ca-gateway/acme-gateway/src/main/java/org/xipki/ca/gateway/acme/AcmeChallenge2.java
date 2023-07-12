// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.util.Args;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge2 {

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

}
