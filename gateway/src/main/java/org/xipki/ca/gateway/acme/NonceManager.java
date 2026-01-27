// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.misc.LogUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class NonceManager {

  private static final Logger LOG = LoggerFactory.getLogger(NonceManager.class);

  private final AtomicLong lastCleanUp = new AtomicLong();

  private final ConcurrentHashMap<String, Long> noncePool =
      new ConcurrentHashMap<>();

  private final int nonceNumBytes;

  // default to 10 minutes
  private long validityMs = 10L * 60 * 1000;

  private final SecureRandom rnd = new SecureRandom();

  public NonceManager(int nonceNumBytes) {
    this.nonceNumBytes = nonceNumBytes;
    // read saved nonces (which are still valid) from file.
    File nonceFile = new File(".nonces");
    if (!nonceFile.exists()) {
      return;
    }

    long now = Clock.systemUTC().millis();
    long maxNotAftter = now + 10000; // + 10 seconds

    int sum = 0;
    try (BufferedReader reader =
             new BufferedReader(new FileReader(nonceFile))) {
      String line;
      while ((line = reader.readLine()) != null) {
        StringTokenizer tokenizer = new StringTokenizer(line, ":");
        String nonce = tokenizer.nextToken();
        long notAfter = Math.min(maxNotAftter,
            Long.parseLong(tokenizer.nextToken(), 16));

        if (notAfter > now) {
          sum++;
          noncePool.put(nonce, notAfter);
        }
      }
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "error reading nonces");
    }

    LOG.info("restored {} nonces", sum);
  }

  public long getValidityMs() {
    return validityMs;
  }

  public void setValidityMs(long validityMs) {
    this.validityMs = validityMs;
  }

  public String newNonce() {
    if (noncePool.size() > 9999) { // more than 9999 nonces in the memory.
      long now = Clock.systemUTC().millis();
      if (now > lastCleanUp.get() + 10000) { // 10 seconds
        for (Map.Entry<String, Long> entry : noncePool.entrySet()) {
          if (entry.getValue() < now) {
            noncePool.remove(entry.getKey());
          }
        }
      }
      lastCleanUp.set(now);
    }

    byte[] nonce = new byte[nonceNumBytes];
    rnd.nextBytes(nonce);
    String nonceText = Base64.getUrlNoPaddingEncoder().encodeToString(nonce);
    noncePool.put(nonceText, Clock.systemUTC().millis() + validityMs);
    return nonceText;
  }

  public boolean removeNonce(String nonce) {
    return null != noncePool.remove(nonce);
  }

  public void close() {
    if (noncePool.isEmpty()) {
      return;
    }

    long now = Clock.systemUTC().millis();

    // save the unused nonces
    int sum = 0;
    try (OutputStream os = Files.newOutputStream(Paths.get(".nonces"),
        StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
      for (Map.Entry<String, Long> entry : noncePool.entrySet()) {
        if (entry.getValue() < now) {
          continue;
        }

        sum++;
        String line = entry.getKey() + ":" +
            Long.toString(entry.getValue(), 16) + "\n";
        os.write(line.getBytes(StandardCharsets.UTF_8));
      }
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "error saving nonces");
    }

    LOG.info("saved {} nonces", sum);
  }

}
