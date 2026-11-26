// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.CaConfigurationRequest;

/**
 * Stores public operation metadata only. CAS protects each remote mutation boundary.
 *
 * @author palos
 */
public class CaEnrollmentRepository {
  public enum Status {
    PREPARED,
    AWAITING_CERTIFICATE,
    ISSUING,
    CERTIFICATE_READY,
    REGISTERING,
    REGISTERED,
    RESULT_UNKNOWN,
    FAILED,
    CANCELLED
  }

  public static class Data {
    public String name,
        mode,
        parentCa,
        parentFingerprint,
        profile,
        profileHash,
        csr,
        csrFingerprint,
        subjectKeyFingerprint;
    public String notBefore, notAfter, certificate, diagnostic, stage, keyType;
    public String module, keyId, keyLabel, signatureAlgorithm;
    public Integer slotIndex;
    public String issuedSubject, issuedIssuer, issuedNotBefore, issuedNotAfter;
    public Integer issuedPathLength;
    public List<String> certificateChain = List.of();
    public CaConfigurationRequest config;
    public boolean acceptUnknownRevocation;
  }

  public record Operation(
      String operationId, long ownerId, String purpose, Status status, long version, Data data) {}

  private final Jdbc jdbc;

  public CaEnrollmentRepository(Jdbc jdbc) {
    this.jdbc = jdbc;
  }

  private Operation row(ResultSet r, int n) throws SQLException {
    try {
      return new Operation(
          r.getString("operation_id"),
          r.getLong("owner_id"),
          r.getString("purpose"),
          Status.valueOf(r.getString("status")),
          r.getLong("version"),
          Json.read(r.getString("public_json"), Data.class));
    } catch (Exception ex) {
      throw new SQLException("Invalid enrollment metadata");
    }
  }

  private String encode(Data data) {
    try {
      return Json.write(data);
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid enrollment metadata");
    }
  }

  public Operation get(String id) {
    UUID.fromString(id);
    var results = jdbc.query("SELECT * FROM web_ca_enrollment WHERE operation_id=?", this::row, id);
    if (results.isEmpty()) {
      throw new ApiException(404, "Resource not found");
    }
    return results.get(0);
  }

  public Operation idempotent(long owner, String key, String hash) {
    var rows =
        jdbc.query(
            "SELECT * FROM web_ca_enrollment WHERE owner_id=? AND idempotency_key=?",
            this::row,
            owner,
            key);
    if (rows.isEmpty()) {
      return null;
    }
    String actual =
        jdbc.queryForObject(
            "SELECT request_hash FROM web_ca_enrollment WHERE operation_id=?",
            String.class,
            rows.get(0).operationId());
    if (!hash.equals(actual)) {
      throw conflict();
    }
    return rows.get(0);
  }

  public List<Operation> list(long owner, boolean all) {
    return all
        ? jdbc.query(
            "SELECT * FROM web_ca_enrollment ORDER BY created_at DESC LIMIT 100", this::row)
        : jdbc.query(
            "SELECT * FROM web_ca_enrollment WHERE owner_id=? ORDER BY created_at DESC LIMIT 100",
            this::row,
            owner);
  }

  public Operation create(
      String id, long owner, String key, String hash, String purpose, Status status, Data data) {
    jdbc.update(
        "INSERT INTO"
            + " web_ca_enrollment(operation_id,owner_id,idempotency_key,request_hash,"
            + "purpose,status,public_json)"
            + " VALUES (?,?,?,?,?,?,?)",
        id,
        owner,
        key,
        hash,
        purpose,
        status.name(),
        encode(data));
    return get(id);
  }

  public long pendingForParent(String fingerprint) {
    Long count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM web_ca_enrollment WHERE status NOT IN ('REGISTERED','CANCELLED')"
                + " AND JSON_UNQUOTE(JSON_EXTRACT(public_json,'$.parentFingerprint'))=?",
            Long.class,
            fingerprint);
    return count == null ? 0 : count;
  }

  public Operation move(Operation from, Status next, Data data) {
    if (jdbc.update(
            "UPDATE web_ca_enrollment SET"
                + " status=?,version=version+1,public_json=?,updated_at=CURRENT_TIMESTAMP(3) WHERE"
                + " operation_id=? AND version=? AND status=?",
            next.name(),
            encode(data),
            from.operationId(),
            from.version(),
            from.status().name())
        != 1) {
      throw conflict();
    }
    return get(from.operationId());
  }

  public static ApiException conflict() {
    return new ApiException(
        409, "Enrollment state changed; reload the operation before continuing");
  }
}
