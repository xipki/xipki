// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.xipki.mgmt.web.core.*;

/**
 * Operation-bound encrypted secrets. Neither passwords nor private keys enter JDBC.
 *
 * @author palos
 */
public class EnrollmentKeyStore {
  private final String secretFile, directory;

  public EnrollmentKeyStore(String secretFile, String directory) {
    this.secretFile = secretFile;
    this.directory = directory;
  }

  private byte[] secret() throws Exception {
    if (secretFile.isBlank() || directory.isBlank()) {
      throw new IllegalStateException(
          "Hosted enrollment requires an encryption secret and persistent key directory");
    }
    var dir = Path.of(directory);
    if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) || !Files.isWritable(dir)) {
      throw new IllegalStateException("Enrollment key directory is unavailable");
    }
    byte[] key = Files.readAllBytes(Path.of(secretFile));
    if (key.length != 32) {
      throw new IllegalStateException("Enrollment encryption secret must contain exactly 32 bytes");
    }
    return key;
  }

  public void requireAvailable() {
    try {
      var key = secret();
      Arrays.fill(key, (byte) 0);
    } catch (Exception ex) {
      throw new IllegalStateException(
          "Hosted enrollment requires a 32-byte secret and a persistent writable key directory");
    }
  }

  private Path path(String id) {
    return Path.of(directory, UUID.fromString(id) + ".key");
  }

  public void put(String id, String value) {
    byte[] key = null;
    Path temporary = null;
    try {
      key = secret();
      var target = path(id);
      if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
        throw new IllegalStateException();
      }
      byte[] nonce = new byte[12];
      new SecureRandom().nextBytes(nonce);
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
      cipher.updateAAD(id.getBytes(StandardCharsets.US_ASCII));
      byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
      temporary =
          Files.createTempFile(
              Path.of(directory),
              ".enrollment-",
              ".tmp",
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
        var buffer =
            ByteBuffer.wrap(
                ByteBuffer.allocate(12 + encrypted.length).put(nonce).put(encrypted).array());
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      }
      // A hard link publishes the complete file atomically and cannot overwrite an existing
      // operation.
      Files.createLink(target, temporary);
      try (var dir = FileChannel.open(Path.of(directory), StandardOpenOption.READ)) {
        dir.force(true);
      }
    } catch (Exception ex) {
      throw new IllegalStateException("Cannot protect enrollment key material");
    } finally {
      if (key != null) {
        Arrays.fill(key, (byte) 0);
      }
      if (temporary != null) {
        try {
          Files.deleteIfExists(temporary);
        } catch (Exception ignored) {
        }
      }
    }
  }

  public String get(String id) {
    byte[] key = null;
    try {
      key = secret();
      var file = path(id);
      if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
          || Files.size(file) > 4 * 1024 * 1024) {
        throw new IllegalStateException();
      }
      byte[] bytes = Files.readAllBytes(file);
      if (bytes.length < 28) {
        throw new IllegalStateException();
      }
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new GCMParameterSpec(128, Arrays.copyOf(bytes, 12)));
      cipher.updateAAD(id.getBytes(StandardCharsets.US_ASCII));
      return new String(cipher.doFinal(bytes, 12, bytes.length - 12), StandardCharsets.UTF_8);
    } catch (Exception ex) {
      throw new IllegalStateException(
          "Enrollment key material is unavailable or cannot be authenticated");
    } finally {
      if (key != null) {
        Arrays.fill(key, (byte) 0);
      }
    }
  }

  /** Only server-generated operation IDs can address the dedicated key directory. */
  public boolean remove(String id) {
    try {
      requireAvailable();
      Files.deleteIfExists(path(id));
      try (var dir = FileChannel.open(Path.of(directory), StandardOpenOption.READ)) {
        dir.force(true);
      }
      return true;
    } catch (Exception ex) {
      return false;
    }
  }
}
