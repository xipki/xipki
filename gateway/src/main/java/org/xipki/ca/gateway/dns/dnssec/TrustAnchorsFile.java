// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.xipki.ca.gateway.dns.DnsName;
import org.xipki.ca.gateway.dns.DnsRecord;
import org.xipki.codec.Base64;
import org.xipki.codec.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * File with trust anchors that is reloaded when its modification time or size changes.
 * <p>
 * The trust anchors are in zone-file format. Only DS and DNSKEY records are accepted, e.g.
 * <pre>
 * . 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
 * </pre>
 * Comments start with ';', or with '#' at the beginning of a line. Parentheses may
 * be used to continue a record over several lines.
 *
 * @author Lijun Liao (xipki)
 */
public class TrustAnchorsFile {

  private final Path path;

  private FileTime lastModified;

  private long lastSize = -1;

  public TrustAnchorsFile(Path path) {
    this.path = Objects.requireNonNull(path, "path");
  }

  public Path path() {
    return path;
  }

  /**
   * Loads the trust anchors and remembers the modification time and size of the file.
   *
   * @return the trust anchors, not empty.
   * @throws IOException if the file cannot be read, is invalid, or contains no anchors.
   */
  public List<DnsRecord> load() throws IOException {
    FileTime modified = Files.getLastModifiedTime(path);
    long size = Files.size(path);
    // Remember the state before parsing, so that an invalid file is reported only
    // once, and again after it has been changed.
    lastModified = modified;
    lastSize = size;

    List<DnsRecord> anchors;
    try (InputStream in = Files.newInputStream(path)) {
      anchors = parse(in);
    }

    if (anchors.isEmpty()) {
      throw new IOException("no trust anchors in " + path);
    }
    return anchors;
  }

  /**
   * Reloads the trust anchors if the modification time or size of the file has changed
   * since the last {@link #load()}.
   *
   * @return the new trust anchors, or {@code null} if the file is unchanged.
   * @throws IOException if the file cannot be read, is invalid, or contains no anchors.
   */
  public List<DnsRecord> loadIfChanged() throws IOException {
    FileTime modified = Files.getLastModifiedTime(path);
    long size = Files.size(path);
    if (modified.equals(lastModified) && size == lastSize) {
      return null;
    }
    return load();
  }

  public static List<DnsRecord> parse(InputStream in) throws IOException {
    List<DnsRecord> ret = new ArrayList<>();
    BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));

    StringBuilder entry = new StringBuilder();
    int depth = 0;
    String line;
    int lineNo = 0;
    while ((line = reader.readLine()) != null) {
      lineNo++;
      if (line.trim().startsWith("#")) {
        continue;
      }

      int idx = line.indexOf(';');
      if (idx != -1) {
        line = line.substring(0, idx);
      }

      for (int i = 0; i < line.length(); i++) {
        char c = line.charAt(i);
        if (c == '(') {
          depth++;
          entry.append(' ');
        } else if (c == ')') {
          if (--depth < 0) {
            throw new IOException("unbalanced ')' in line " + lineNo);
          }
          entry.append(' ');
        } else {
          entry.append(c);
        }
      }

      if (depth == 0) {
        String text = entry.toString().trim();
        entry.setLength(0);
        if (!text.isEmpty()) {
          ret.add(parseRecord(text, lineNo));
        }
      } else {
        entry.append(' ');
      }
    }

    if (depth != 0) {
      throw new IOException("unbalanced '(' at end of trust anchors");
    }
    return ret;
  }

  private static DnsRecord parseRecord(String text, int lineNo) throws IOException {
    String[] tokens = text.split("\\s+");
    try {
      DnsName owner = DnsName.of(tokens[0]);
      long ttl = 0;
      int i = 1;
      // optional TTL and class, in any order
      for (int n = 0; n < 2 && i < tokens.length; n++) {
        if (tokens[i].matches("\\d+")) {
          ttl = Long.parseLong(tokens[i++]);
        } else if (tokens[i].equalsIgnoreCase("IN")) {
          i++;
        }
      }

      if (i >= tokens.length) {
        throw new IOException("missing type");
      }

      String type = tokens[i++].toUpperCase(Locale.ROOT);
      String[] rdata = Arrays.copyOfRange(tokens, i, tokens.length);
      if (type.equals("DS")) {
        return new DnsRecord(owner, DnsRecord.TYPE_DS, DnsRecord.CLASS_IN, ttl, dsRdata(rdata));
      } else if (type.equals("DNSKEY")) {
        return new DnsRecord(owner, DnsRecord.TYPE_DNSKEY, DnsRecord.CLASS_IN, ttl,
            dnskeyRdata(rdata));
      } else {
        throw new IOException("unsupported type " + type);
      }
    } catch (IOException | RuntimeException ex) {
      throw new IOException("invalid trust anchor in line " + lineNo + ": " + ex.getMessage(),
          ex);
    }
  }

  private static byte[] dsRdata(String[] tokens) throws IOException {
    if (tokens.length < 4) {
      throw new IOException("invalid DS record");
    }
    byte[] digest = Hex.decode(String.join("", Arrays.copyOfRange(tokens, 3, tokens.length)));
    return withHeader(Integer.parseInt(tokens[0]), Integer.parseInt(tokens[1]),
        Integer.parseInt(tokens[2]), digest);
  }

  private static byte[] dnskeyRdata(String[] tokens) throws IOException {
    if (tokens.length < 4) {
      throw new IOException("invalid DNSKEY record");
    }
    byte[] key = Base64.decode(String.join("", Arrays.copyOfRange(tokens, 3, tokens.length)));
    return withHeader(Integer.parseInt(tokens[0]), Integer.parseInt(tokens[1]),
        Integer.parseInt(tokens[2]), key);
  }

  // u16 || u8 || u8 || data, the common layout of DS and DNSKEY RDATA
  private static byte[] withHeader(int u16, int u8a, int u8b, byte[] data) throws IOException {
    if (u16 < 0 || u16 > 0xFFFF || u8a < 0 || u8a > 0xFF || u8b < 0 || u8b > 0xFF
        || data == null || data.length == 0) {
      throw new IOException("field out of range");
    }
    byte[] rdata = new byte[4 + data.length];
    rdata[0] = (byte) (u16 >>> 8);
    rdata[1] = (byte) u16;
    rdata[2] = (byte) u8a;
    rdata[3] = (byte) u8b;
    System.arraycopy(data, 0, rdata, 4, data.length);
    return rdata;
  }

}
