// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.security.AccessControl.CaIdentity;

/**
 * @author palos
 */
public class CertificateOwnership {
  private static final int PAGE_SIZE = 5;

  private record Entry(String serial, Instant issuedAt) {}

  public record Page(List<String> serials, String nextCursor) {}

  private final Jdbc jdbc;

  public CertificateOwnership(Jdbc jdbc) {
    this.jdbc = jdbc;
  }

  public void record(CaIdentity ca, String serial, String profile) {
    jdbc.update(
        "INSERT INTO"
            + " web_certificate_owner(ca_name,ca_fingerprint,serial_number,user_id,profile_name)"
            + " VALUES (?,?,?,?,?)",
        ca.name(),
        ca.fingerprint(),
        serial,
        AccountService.principal().id(),
        profile);
  }

  public boolean owns(CaIdentity ca, String serial) {
    return jdbc.queryForObject(
            "SELECT COUNT(*) FROM web_certificate_owner WHERE ca_name=? AND ca_fingerprint=? AND"
                + " serial_number=? AND user_id=?",
            Integer.class,
            ca.name(),
            ca.fingerprint(),
            serial,
            AccountService.principal().id())
        == 1;
  }

  public List<String> serials(CaIdentity ca, int limit) {
    if (limit < 1 || limit > 1001) {
      throw new IllegalArgumentException("Invalid limit");
    }
    return jdbc.queryForList(
        "SELECT serial_number FROM web_certificate_owner WHERE ca_name=? AND ca_fingerprint=? AND"
            + " user_id=? ORDER BY issued_at DESC,serial_number LIMIT ?",
        String.class,
        ca.name(),
        ca.fingerprint(),
        AccountService.principal().id(),
        limit);
  }

  public Page page(CaIdentity ca, String cursor) {
    Entry after = decode(cursor);
    String sql =
        "SELECT serial_number,issued_at FROM web_certificate_owner WHERE ca_name=? AND"
            + " ca_fingerprint=? AND user_id=?"
            + (after == null ? "" : " AND (issued_at<? OR (issued_at=? AND serial_number>?))")
            + " ORDER BY issued_at DESC,serial_number LIMIT ?";
    Object[] args =
        after == null
            ? new Object[] {
              ca.name(), ca.fingerprint(), AccountService.principal().id(), PAGE_SIZE + 1
            }
            : new Object[] {
              ca.name(),
              ca.fingerprint(),
              AccountService.principal().id(),
              Timestamp.from(after.issuedAt()),
              Timestamp.from(after.issuedAt()),
              after.serial(),
              PAGE_SIZE + 1
            };
    List<Entry> rows =
        jdbc.query(
            sql,
            (result, row) -> new Entry(result.getString(1), result.getTimestamp(2).toInstant()),
            args);
    boolean more = rows.size() > PAGE_SIZE;
    int count = Math.min(rows.size(), PAGE_SIZE);
    var serials = new ArrayList<String>(count);
    for (int i = 0; i < count; i++) {
      serials.add(rows.get(i).serial());
    }
    return new Page(serials, more ? encode(rows.get(count - 1)) : null);
  }

  private static String encode(Entry entry) {
    String value = entry.issuedAt().toEpochMilli() + ":" + entry.serial();
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.US_ASCII));
  }

  private static Entry decode(String cursor) {
    if (cursor == null) {
      return null;
    }
    try {
      if (cursor.length() > 256) {
        throw new IllegalArgumentException();
      }
      String value = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.US_ASCII);
      int colon = value.indexOf(':');
      if (colon < 1 || !value.substring(colon + 1).matches("[0-9a-f]{1,160}")) {
        throw new IllegalArgumentException();
      }
      return new Entry(
          value.substring(colon + 1),
          Instant.ofEpochMilli(Long.parseLong(value.substring(0, colon))));
    } catch (RuntimeException ex) {
      throw new IllegalArgumentException("Invalid certificate cursor");
    }
  }
}
