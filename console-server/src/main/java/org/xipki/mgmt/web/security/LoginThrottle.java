// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * Bounded account and source attempts, shared across replicas; no unbounded in-memory key map.
 *
 * @author palos
 */
public class LoginThrottle {
  private final Jdbc jdbc;
  private final Transactions transaction;

  public LoginThrottle(Jdbc jdbc, Transactions manager) {
    this.jdbc = jdbc;
    transaction = manager;
  }

  /** Reserves one bounded login attempt for both the account and source address. */
  public void reserve(String username, String source) {
    transaction.executeWithoutResult(
        status -> {
          var keys = new TreeMap<String, Integer>();
          keys.put(accountKey(username), 8);
          keys.put(key("ip:" + source), 80);
          for (var entry : keys.entrySet()) {
            jdbc.insertIfAbsent(
                "INSERT INTO web_login_throttle(throttle_key) VALUES (?)",
                entry.getKey());
            jdbc.queryForObject(
                "SELECT attempts FROM web_login_throttle WHERE throttle_key=? FOR UPDATE",
                Integer.class,
                entry.getKey());
            jdbc.update(
                "UPDATE web_login_throttle SET attempts=0,window_start=CURRENT_TIMESTAMP(3) WHERE"
                    + " throttle_key=? AND"
                    + " window_start<?",
                entry.getKey(),
                Instant.now().minus(Duration.ofMinutes(15)));
            int attempts =
                jdbc.queryForObject(
                    "SELECT attempts FROM web_login_throttle WHERE throttle_key=?",
                    Integer.class,
                    entry.getKey());
            if (attempts >= entry.getValue()) {
              throw new ApiException(429, "Request rejected");
            }
            jdbc.update(
                "UPDATE web_login_throttle SET attempts=attempts+1 WHERE throttle_key=?",
                entry.getKey());
          }
          var expired =
              jdbc.queryForList(
                  "SELECT throttle_key FROM web_login_throttle WHERE window_start<? ORDER BY"
                      + " window_start LIMIT 200",
                  String.class,
                  Instant.now().minus(Duration.ofDays(1)));
          for (String throttleKey : expired) {
            jdbc.update("DELETE FROM web_login_throttle WHERE throttle_key=?", throttleKey);
          }
        });
  }

  public void success(String username) {
    jdbc.update("DELETE FROM web_login_throttle WHERE throttle_key=?", accountKey(username));
  }

  private String accountKey(String input) {
    // Match authentication's database collation: case/accent-equivalent
    // spellings must not create new attempt buckets for the same account.
    var names =
        jdbc.queryForList("SELECT username FROM web_user WHERE username=?", String.class, input);
    return key("user:" + normalized(names.isEmpty() ? input : names.get(0)));
  }

  private static String normalized(String value) {
    return value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
  }

  private static String key(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }
}
