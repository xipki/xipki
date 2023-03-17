// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The Mac protected audit service.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class MacAuditService implements AuditService {

  public static final String KEY_SHARD_ID = "shard-id";

  public static final String KEY_ALGO = "algo";

  public static final String KEY_PASSWORD = "password";

  public static final String KEY_KEYID = "keyid";

  public static final String KEY_OLD_PASSWORD = "old-password";

  public static final String KEY_OLD_KEYID = "old-keyid";

  public static final String KEY_ENC_INTERVAL = "enc-interval";

  private static final int ALGO_ID_HMAC_SHA256 = 1;

  private static final String VERSION_V1 = "v1";

  protected static final String DELIM = ";";

  private static final String INNER_DELIM = ":";

  private static final Logger LOG = LoggerFactory.getLogger(MacAuditService.class);

  private static final DateTimeFormatter DTF = DateTimeFormatter.ofPattern("yyyy.MM.dd-HH:mm:ss.SSS");

  private final ZoneId timeZone = ZoneId.systemDefault();

  protected int shardId;

  protected AtomicLong id = new AtomicLong(0);

  protected String previousTag;

  private String algo;

  private String tagPrefix;

  private byte[] tagPrefixBytes;

  private String keyId;

  private SecureRandom rnd;

  private SecretKey macKey;

  private SecretKey encKey;

  private Mac mac;

  private Cipher cipher;

  private int encInterval;

  public MacAuditService() {
  }

  protected String formatDate(Instant date) {
    return DTF.format(date.atZone(timeZone));
  }

  private String buildMacPayload(Instant date, long thisId, int eventType, String levelText,
                                 long previousId, String previousTag, String message) {
    return formatDate(date) + DELIM + levelText + DELIM + eventType + DELIM + shardId + DELIM + thisId
        + DELIM + previousId + INNER_DELIM + (previousTag == null ? "" : previousTag) + DELIM + message;
  }

  protected abstract void storeLog(
          Instant date, long thisId, int eventType, String levelText,
          long previousId, String message, String thisTag);

  protected abstract void storeIntegrity(String integrityText);

  protected abstract void doClose() throws Exception;

  protected void doExtraInit(ConfPairs confPairs, PasswordResolver passwordResolver)
          throws PasswordResolverException {
  }

  protected void verify(long id, String tag, String integrityText, ConfPairs confPairs) {
    if (id == 0) {
      // found no audit entry
      if (StringUtil.isBlank(integrityText)) {
        return;
      } else {
        throw new IllegalStateException("audit entry deleted unexpectedly");
      }
    } else if (StringUtil.isBlank(integrityText)) {
      throw new IllegalStateException("integrityText deleted unexpectedly");
    }

    StringTokenizer tokenizer = new StringTokenizer(integrityText, DELIM);
    String version = tokenizer.nextToken();
    if (!VERSION_V1.equalsIgnoreCase(version)) {
      throw new IllegalStateException("unknown version " + version);
    }

    String thisKeyId = tokenizer.nextToken();
    byte[] iv = Base64.decodeFast(tokenizer.nextToken());
    byte[] cipherText = Base64.decodeFast(tokenizer.nextToken());

    SecretKey decryptionKey;
    if (keyId.equals(thisKeyId)) {
      decryptionKey = encKey;
    } else {
      String oldKeyId = confPairs.value(KEY_OLD_KEYID);
      if (!thisKeyId.equals(oldKeyId)) {
        throw new IllegalStateException("found no key to decrypt the integrityText");
      }

      String password = confPairs.value(KEY_OLD_PASSWORD);
      try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        char[] passwordChars = password.toCharArray();
        KeySpec spec = new PBEKeySpec(passwordChars, "ENC".getBytes(StandardCharsets.UTF_8), 10000, 256);
        decryptionKey = factory.generateSecret(spec);
      } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
        throw new IllegalStateException("error deriving key", ex);
      }
    }

    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    String plaintext;
    try {
      cipher.init(Cipher.DECRYPT_MODE, decryptionKey, spec);
      plaintext = new String(cipher.doFinal(cipherText));
    } catch (Exception ex) {
      throw new IllegalStateException("error while decrypting the integrityText");
    }

    tokenizer = new StringTokenizer(plaintext, DELIM);
    version = tokenizer.nextToken();
    if (!VERSION_V1.equalsIgnoreCase(version)) {
      throw new IllegalStateException("unknown version " + version);
    }

    int integrityShardId = Integer.parseInt(tokenizer.nextToken());
    long integrityId = Long.parseLong(tokenizer.nextToken());
    String thisTag = tokenizer.nextToken();
    if (integrityShardId != this.shardId) {
      throw new IllegalStateException(String.format(
              "shardId in integrityText (%d) != configured shardId (%d)", integrityShardId, this.shardId));
    }

    if (integrityId == id) {
      if (!tag.equals(thisTag)) {
        throw new IllegalStateException("tag in integrityText does not match the audit entry.");
      }
    } else if (integrityId > id) {
      throw new IllegalStateException(String.format(
              "audit entries deleted unexpectedly, id in the latest entry is %d, but expected %d", id, integrityId));
    } else {
      LOG.warn("id in the last entry is{}, but in the integrityText is {}", id, integrityId);
    }
  }

  @Override
  public void init(String conf) {
    try {
      init(conf, null);
    } catch (PasswordResolverException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Override
  public void init(String conf, PasswordResolver passwordResolver)
          throws PasswordResolverException {
    ConfPairs confPairs = new ConfPairs(conf);
    String str = confPairs.value(KEY_SHARD_ID);
    shardId = StringUtil.isBlank(str) ? 0 : Integer.parseInt(str);

    str = confPairs.value(KEY_ENC_INTERVAL);
    encInterval = (str == null) ? 1 : Integer.parseInt(str);

    algo = confPairs.value(KEY_ALGO);
    int algoId;
    if (algo == null) {
      algo = "HmacSHA256";
      algoId = ALGO_ID_HMAC_SHA256;
    } else {
      if ("HmacSHA256".equalsIgnoreCase(algo.replace("-", ""))) {
        algo = "HmacSHA256";
        algoId = ALGO_ID_HMAC_SHA256;
      } else {
        throw new IllegalArgumentException("unsupported algorithm " + algo);
      }
    }

    keyId = confPairs.value(KEY_KEYID);
    if (StringUtil.isBlank(keyId)) {
      throw new IllegalArgumentException("property " + KEY_KEYID + " not defined");
    }

    this.tagPrefix = VERSION_V1 + INNER_DELIM + algoId + INNER_DELIM + keyId + INNER_DELIM;
    this.tagPrefixBytes = tagPrefix.getBytes(StandardCharsets.UTF_8);
    String password = confPairs.value(KEY_PASSWORD);
    if (StringUtil.isBlank(password)) {
      throw new IllegalArgumentException("property " + KEY_PASSWORD + " not defined");
    }

    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      char[] passwordChars = password.toCharArray();
      KeySpec spec = new PBEKeySpec(passwordChars, "MAC".getBytes(StandardCharsets.UTF_8), 10000, 256);
      macKey = factory.generateSecret(spec);

      spec = new PBEKeySpec(passwordChars, "ENC".getBytes(StandardCharsets.UTF_8), 10000, 256);
      encKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

      mac = Mac.getInstance(algo);
      mac.init(macKey);

      cipher = Cipher.getInstance("AES/GCM/NoPadding");
    } catch (Exception ex) {
      throw new IllegalStateException("could not initialize Mac or Cipher", ex);
    }

    this.rnd = new SecureRandom();
    doExtraInit(new ConfPairs(conf), passwordResolver);
  }

  @Override
  public void logEvent(AuditEvent event) {
    log(AuditService.AUDIT_EVENT, event.getLevel(), event.toTextMessage());
  }

  @Override
  public void logEvent(PciAuditEvent event) {
    log(AuditService.PCI_AUDIT_EVENT, event.getLevel(), event.toTextMessage());
  }

  private synchronized void log(int eventType, AuditLevel level, String message) {
    Instant date = Instant.now();
    long previousId = id.get();
    long thisId = id.incrementAndGet();
    String levelText = level.getText();

    String payload = buildMacPayload(date, thisId, eventType, levelText, previousId, previousTag, message);

    mac.reset();
    mac.update(tagPrefixBytes);
    mac.update(payload.getBytes(StandardCharsets.UTF_8));
    byte[] tag = mac.doFinal();
    String tagWithMeta = tagPrefix + Base64.encodeToString(tag);
    this.previousTag = tagWithMeta;

    storeLog(date, thisId, eventType, levelText, previousId, message, tagWithMeta);
    if (encInterval <= 1 || thisId % encInterval == 0) {
      String integrityText = buildIntegrityText();
      storeIntegrity(integrityText);
    }
  }

  private String buildIntegrityText() {
    byte[] plaintext = StringUtil.toUtf8Bytes(VERSION_V1 + DELIM + shardId + DELIM + id.get() + DELIM + previousTag);

    byte[] iv = new byte[12];
    rnd.nextBytes(iv);
    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    byte[] cipherText;
    try {
      cipher.init(Cipher.ENCRYPT_MODE, encKey, spec);
      cipherText = cipher.doFinal(plaintext);
    } catch (Exception e) {
      throw new IllegalStateException("error encrypting thisId", e);
    }
    return VERSION_V1 + DELIM + keyId + DELIM + Base64.encodeToString(iv) + DELIM + Base64.encodeToString(cipherText);
  }

  @Override
  public final void close() throws Exception {
    if (!(encInterval <= 1 | id.get() % encInterval == 0)) {
      String integrityText = buildIntegrityText();
      storeIntegrity(integrityText);
    }

    doClose();
  }

}
