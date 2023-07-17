// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.util.Base64Url;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class NonceManager {

  // TODO: remove expired nonces
  private final ConcurrentHashMap<String, Long> noncePool = new ConcurrentHashMap<>();

  private final int nonceNumBytes;

  // default to 10 minutes
  private long validityMs = 10L * 60 * 1000;

  private final SecureRandom rnd = new SecureRandom();

  public NonceManager(int nonceNumBytes) {
    this.nonceNumBytes = nonceNumBytes;
  }

  public long getValidityMs() {
    return validityMs;
  }

  public void setValidityMs(long validityMs) {
    this.validityMs = validityMs;
  }

  public String newNonce() {
    byte[] nonce = new byte[nonceNumBytes];
    rnd.nextBytes(nonce);
    String nonceText = Base64Url.encodeToStringNoPadding(nonce);
    noncePool.put(nonceText, Clock.systemUTC().millis() + validityMs);
    return nonceText;
  }

  public boolean removeNonce(String nonce) {
    return null != noncePool.remove(nonce);
  }

  public boolean containsNonce(String nonce) {
    return noncePool.containsKey(nonce);
  }

  public void destroy() {
    // TODO: save the nonce
  }

}
