// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.*;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.asn1.Asn1StreamParser;
import org.xipki.security.util.JSON;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.xipki.util.CompareUtil.equalsObject;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeDataSource {

  private static final String SQL_ADD_ACCOUNT =
      "INSERT INTO ACCOUNT (ID,LUPDATE,STATUS,JWK_SHA256,DATA) VALUES (?,?,?,?,?)";

  private static final String SQL_ADD_ORDER = "INSERT INTO ORDER2 (ID,LUPDATE,ACCOUNT_ID,STATUS,EXPIRES," +
      "CERT_NAFTER,CERT_SHA256,CERTREQ_META,CSR,CERT,AUTHZS) VALUES (?,?,?,?,?,?,?,?,?,?,?)";

  private static final String SQL_ADD_AUTHZ_ID = "INSERT INTO AUTHZ (ID, ORDER_ID) VALUES (?,?)";

  private static final String SQL_DELETE_ORDER_CERT_EXPIRED = "DELETE FROM ORDER2 WHERE CERT_NAFTER<?";

  private static final String SQL_DELETE_NOT_FISINED_ORDER = "DELETE FROM ORDER2 WHERE " +
      "STATUS != " + OrderStatus.valid + " AND EXPIRES<?";

  private static final String SQL_SELECT_ORDER_ID = "SELECT ID FROM ORDER2 WHERE ACCOUNT=?";

  private final String sqlGetAccount;

  private final String sqlGetAccountFowJwkSha256;

  private final String sqlGetOrderById;

  private final String sqlGetOrderByCertSha256;

  private final DataSourceWrapper dataSource;

  public AcmeDataSource(DataSourceWrapper dataSource) {
    this.dataSource = Args.notNull(dataSource, "dataSource");
    this.sqlGetAccount = dataSource.buildSelectFirstSql(1,
        "ID,STATUS,JWK_SHA256,DATA FROM ACCOUNT WHERE ID=?");
    this.sqlGetAccountFowJwkSha256 = dataSource.buildSelectFirstSql(1,
        "ID,STATUS,JWK_SHA256,DATA FROM ACCOUNT WHERE JWK_SHA256=?");
    this.sqlGetOrderById = dataSource.buildSelectFirstSql(1,
        "ACCOUNT_ID,STATUS,EXPIRES,CERTREQ_META,AUTHZS,CERT_SHA256 FROM ORDER2 WHERE ID=?");
    this.sqlGetOrderByCertSha256 = dataSource.buildSelectFirstSql(1,
        "ID,ACCOUNT_ID,STATUS,EXPIRES,CERTREQ_META,AUTHZS FROM ORDER2 WHERE CERT_SHA256=?");
  }

  private PreparedStatement prepareStatement(String sql) throws AcmeSystemException {
    try {
      return dataSource.prepareStatement(sql);
    } catch (DataAccessException ex) {
      throw new AcmeSystemException(ex);
    }
  } // method prepareStatement

  public void addNewAccount(AcmeAccount account) {
    if (account.getId() == 0) {
      throw new AcmeSystemException("account.id not set");
    }

    final String sql = SQL_ADD_ACCOUNT;

    PreparedStatement ps = prepareStatement(sql);
    // ID,STATUS,JWK_SHA256,DATA
    try {
      int index = 1;
      ps.setLong(index++, account.getId());
      ps.setLong(index++, Instant.now().getEpochSecond());
      ps.setInt(index++, account.getStatus().getCode());
      ps.setString(index++, account.getJwkSha256());
      ps.setString(index, JSON.toJson(account.getData()));
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public byte[] getCert(long orderId) {
    try {
      String str = dataSource.getFirstStringValue(null, "ORDER2", "CERT", "ID=" + orderId);
      return str == null ? null : Base64Url.decodeFast(str);
    } catch (DataAccessException e) {
      throw new AcmeSystemException(e);
    }
  }

  public byte[] getCsr(long orderId) {
    try {
      String str = dataSource.getFirstStringValue(null, "ORDER2", "CSR", "ID=" + orderId);
      return str == null ? null : Base64Url.decodeFast(str);
    } catch (DataAccessException e) {
      throw new AcmeSystemException(e);
    }
  }

  public AcmeAccount getAccount(long accountId) {
    // STATUS,DATA FROM ACCOUNT
    PreparedStatement ps = prepareStatement(sqlGetAccount);
    try {
      ps.setLong(1, accountId);
      return getAccount(ps, sqlGetAccount);
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sqlGetAccount, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public void updateAccount(AcmeAccount oldAccount, AcmeAccount newAccount) {
    if (oldAccount.getId() != newAccount.getId()) {
      throw new IllegalArgumentException("oldAccount and newAccount does not have the same id");
    }

    boolean updateJwkFp = oldAccount.getJwkSha256().equals(newAccount.getJwkSha256());
    boolean updateStatus = oldAccount.getStatus() != newAccount.getStatus();
    String oldData = JSON.toJson(oldAccount.getData());
    String newData = JSON.toJson(newAccount.getData());
    boolean updateData = !oldData.equals(newData);

    if (!(updateJwkFp || updateStatus || updateData)) {
      return;
    }

    StringBuilder sb = new StringBuilder();
    sb.append("UPDATE ACCOUNT SET LUPDATE=?,");
    if (updateStatus) {
      sb.append("STATUS=?,");
    }

    if (updateJwkFp) {
      sb.append("JWK_SHA256=?,");
    }

    if (updateData) {
      sb.append("DATA=?,");
    }

    sb.deleteCharAt(sb.length() - 1);
    sb.append(" WHERE ID=").append(oldAccount.getId());

    String sql = sb.toString();
    PreparedStatement ps = prepareStatement(sql);
    try {
      int index = 1;
      ps.setLong(index++, Instant.now().getEpochSecond());

      if (updateStatus) {
        ps.setInt(index++, newAccount.getStatus().getCode());
      }

      if (updateJwkFp) {
        ps.setString(index++, newAccount.getJwkSha256());
      }

      if (updateData) {
        ps.setString(index, newData);
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public AcmeAccount getAccountForJwk(Map<String, String> jwk) {
    String sha256 = AcmeUtils.jwkSha256(jwk);
    final String sql = sqlGetAccountFowJwkSha256;
    PreparedStatement ps = prepareStatement(sql);
    try {
      ps.setString(1, sha256);
      return getAccount(ps, sql);
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  private AcmeAccount getAccount(PreparedStatement ps, String sql) {
    // ID,JWK_SHA256,STATUS,DATA FROM ACCOUNT
    ResultSet rs = null;
    try {
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      AccountStatus status = AccountStatus.ofCode(rs.getInt("STATUS"));
      AcmeAccount.Data data = JSON.parseObject(rs.getString("DATA"), AcmeAccount.Data.class);
      long id = rs.getLong("ID");
      AcmeAccount ret = new AcmeAccount(id, this);
      ret.setData(data);
      ret.setStatus(status);
      ret.setJwkSha256(rs.getString("JWK_SHA256"));
      ret.setInDb(true);
      ret.mark();

      return ret;
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(null, rs);
    }
  }

  public void addNewOrder(AcmeOrder order) {
    String sql = SQL_ADD_ORDER;

    PreparedStatement ps = prepareStatement(sql);
    // ID,LUPDATE,ACCOUNT,STATUS,EXPIRES,CERT_NAFTER,CERT_SHA256,CERTREQ_META,CSR,CERT,AUTHZS
    try {
      order.updateStatus();

      int index = 1;
      ps.setLong(index++, order.getId());
      ps.setLong(index++, Instant.now().getEpochSecond());
      ps.setLong(index++, order.getAccountId());
      ps.setInt(index++, order.getStatus().getCode());
      ps.setLong(index++, order.getExpires().getEpochSecond());

      byte[] certBytes = order.getCert();
      if (certBytes == null) {
        ps.setNull(index++, Types.BIGINT);
      } else {
        ps.setLong(index++, extractNotAfter(certBytes));
      }
      ps.setString(index++, order.getCertSha256());

      if (order.getCertReqMeta() == null) {
        ps.setNull(index, Types.VARCHAR);
      } else {
        ps.setString(index, JSON.toJson(order.getCertReqMeta()));
      }
      index++;

      if (order.getCsr() == null) {
        ps.setNull(index, Types.VARCHAR);
      } else {
        ps.setString(index, Base64Url.encodeToStringNoPadding(order.getCsr()));
      }
      index++;

      if (certBytes == null) {
        ps.setNull(index, Types.VARCHAR);
      } else {
        ps.setString(index, Base64Url.encodeToStringNoPadding(certBytes));
      }
      index++;

      AcmeAuthzs authzs = new AcmeAuthzs();
      authzs.setAuthzs(order.getAuthzs());
      ps.setString(index, JSON.toJson(authzs));

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }

    sql = SQL_ADD_AUTHZ_ID;
    ps = prepareStatement(sql);
    // ID, ORDER_ID
    try {
      for (AcmeAuthz authz : order.getAuthzs()) {
        ps.setLong(1, authz.getId());
        ps.setLong(2, order.getId());
        ps.addBatch();
      }
      ps.executeBatch();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public void updateOrder(AcmeOrder oldOrder, AcmeOrder newOrder) {
    if (oldOrder.getId() != newOrder.getId()) {
      throw new IllegalArgumentException("oldOrder and newOrder does not have the same id");
    }

    if (oldOrder.getAccountId() != newOrder.getAccountId()) {
      throw new IllegalArgumentException("oldOrder and newOrder does not have the same account");
    }

    newOrder.updateStatus();

    // ACCOUNT_ID,STATUS,EXPIRES,CSR,AUTHZS
    boolean updateStatus = oldOrder.getStatus() != oldOrder.getStatus();
    boolean updateExpires = !equalsObject(oldOrder.getExpires(), newOrder.getExpires());
    boolean updateAuthzs = !equalsObject(oldOrder.getAuthzs(), newOrder.getAuthzs());
    boolean updateCertReqMeta = !equalsObject(oldOrder.getCertReqMeta(), newOrder.getCertReqMeta());
    boolean updateCsr = newOrder.getCsr() != null; // we do not read cert from database to save the bandwidth
    boolean updateCert = newOrder.getCert() != null; // we do not read cert from database to save the bandwidth

    if (!(updateStatus || updateExpires || updateAuthzs || updateCertReqMeta || updateCsr || updateCert)) {
      return;
    }

    StringBuilder sb = new StringBuilder();
    sb.append("UPDATE ORDER2 SET LUPDATE=?,");
    if (updateStatus) {
      sb.append("STATUS=?,");
    }

    if (updateExpires) {
      sb.append("EXPIRES=?,");
    }

    if (updateAuthzs) {
      sb.append("AUTHZS=?,");
    }

    if (updateCertReqMeta) {
      sb.append("CERTREQ_META=?,");
    }

    if (updateCsr) {
      sb.append("CSR=?,");
    }

    if (updateCert) {
      sb.append("CERT_NAFTER=?,CERT_SHA256=?,CERT=?,");
    }

    sb.deleteCharAt(sb.length() - 1);
    sb.append(" WHERE ID=").append(oldOrder.getId());

    String sql = sb.toString();
    PreparedStatement ps = prepareStatement(sql);
    try {
      int index = 1;
      ps.setLong(index++, Instant.now().getEpochSecond());
      if (updateStatus) {
        ps.setInt(index++, newOrder.getStatus().getCode());
      }

      if (updateExpires) {
        ps.setLong(index++, newOrder.getExpires().getEpochSecond());
      }

      if (updateAuthzs) {
        if (newOrder.getAuthzs() == null) {
          ps.setNull(index, Types.VARCHAR);
        } else {
          AcmeAuthzs authzs = new AcmeAuthzs();
          authzs.setAuthzs(newOrder.getAuthzs());
          ps.setString(index, JSON.toJson(authzs));
        }
        index++;
      }

      if (updateCertReqMeta) {
        if (newOrder.getCertReqMeta() == null) {
          ps.setNull(index, Types.VARCHAR);
        } else {
          ps.setString(index, JSON.toJson(newOrder.getCertReqMeta()));
        }
        index++;
      }

      if (updateCsr) {
        ps.setString(index++, Base64Url.encodeToStringNoPadding(newOrder.getCsr()));
      }

      if (updateCert) {
        byte[] certBytes = newOrder.getCert();
        ps.setLong(index++, extractNotAfter(certBytes));
        ps.setString(index++, newOrder.getCertSha256());
        ps.setString(index, Base64Url.encodeToStringNoPadding(certBytes));
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public AcmeOrder getOrder(long orderId) {
    // do not read CSR and CERT to save bandwidth.
    PreparedStatement ps = prepareStatement(sqlGetOrderById);
    ResultSet rs = null;
    try {
      ps.setLong(1, orderId);
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      AcmeOrder order = buildOrder(rs, orderId);
      order.setCertSha256(rs.getString("CERT_SHA256"));
      order.mark();

      return order;
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sqlGetOrderById, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }
  }

  public AcmeOrder getOrderForCertSha256(String certSha256) {
    PreparedStatement ps = prepareStatement(sqlGetOrderByCertSha256);
    ResultSet rs = null;
    try {
      ps.setString(1, certSha256);
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      AcmeOrder order = buildOrder(rs, null);
      order.setCertSha256(certSha256);
      return order;
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sqlGetOrderByCertSha256, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }
  }

  private AcmeOrder buildOrder(ResultSet rs, Long id) throws SQLException {
    // ACCOUNT_ID,STATUS,EXPIRES,CSR,CERT,AUTHZS
    String authzsStr = rs.getString("AUTHZS");
    long accountId = rs.getLong("ACCOUNT_ID");
    if (id == null) {
      id = rs.getLong("ID");
    }

    AcmeOrder order = new AcmeOrder(id, accountId, this);
    order.setStatus(OrderStatus.ofCode(rs.getInt("STATUS")));
    order.setExpires(Instant.ofEpochSecond(rs.getLong("EXPIRES")));
    String str = rs.getString("CERTREQ_META");
    if (str != null) {
      order.setCertReqMeta(JSON.parseObject(str, CertReqMeta.class));
    }

    AcmeAuthzs authzs = JSON.parseObject(authzsStr, AcmeAuthzs.class);
    order.setAuthzs(authzs.getAuthzs());

    return order;
  }

  public AcmeAuthz getAuthz(long authzId) {
    // from database
    Long orderId;
    try {
      orderId = dataSource.getFirstLongValue(null, "AUTHZ", "ORDER_ID", "ID=" + authzId);
    } catch (DataAccessException ex) {
      throw new AcmeSystemException(ex);
    }

    if (orderId != null) {
      AcmeOrder order = getOrder(orderId);
      if (order != null) {
        return order.getAuthz(authzId);
      }
    }

    return null;
  }

  public List<Long> getOrderIds(long accountId) {
    List<Long> orderIds = new LinkedList<>();
    // from database
    final String sql = SQL_SELECT_ORDER_ID;
    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;
    try {
      ps.setLong(1, accountId);
      rs = ps.executeQuery();
      while (rs.next()) {
        long id = rs.getLong("ID");
        if (!orderIds.contains(id)) {
          orderIds.add(id);
        }
      }
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }

    return orderIds;
  }

  public List<ChallId> getChallengesToValidate() {
    List<ChallId> ids =  new LinkedList<>();
    final String sql = dataSource.buildSelectFirstSql(1000, "AUTHZS FROM ORDER2 WHERE STATUS=?");
    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;
    try {
      ps.setInt(1, OrderStatus.pending.getCode());
      rs = ps.executeQuery();
      while (rs.next()) {
        List<AcmeAuthz> authzs = JSON.parseObject(rs.getString("AUTHZS"), AcmeAuthzs.class).getAuthzs();
        addChallengesToValidate(ids, authzs);
      }
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }

    return ids;
  }

  public List<Long> getOrdersToEnroll() {
    List<Long> ids =  new LinkedList<>();
    // add those from database
    final String sql = dataSource.buildSelectFirstSql(1000, "ID FROM ORDER2 WHERE STATUS=?");
    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;
    try {
      ps.setInt(1, OrderStatus.processing.getCode());
      rs = ps.executeQuery();
      while (rs.next()) {
        ids.add(rs.getLong("ID"));
      }
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }
    return ids;
  }

  public int cleanOrders(Instant certNotAfter, Instant notFinishedOrderExpires) {
    // delete order with expired certificates
    Instant dateLimit = Instant.now().minus(10, ChronoUnit.DAYS);
    if (certNotAfter.isAfter(dateLimit)) {
      throw new IllegalArgumentException("certNotAfter " + certNotAfter + " is not allowed");
    }

    if (notFinishedOrderExpires.isAfter(dateLimit)) {
      throw new IllegalArgumentException("notFinishedOrderExpires " + notFinishedOrderExpires + " is not allowed");
    }

    int sum = 0;
    String sql = SQL_DELETE_ORDER_CERT_EXPIRED;
    PreparedStatement ps = prepareStatement(sql);
    try {
      ps.setLong(1, certNotAfter.getEpochSecond());
      sum += ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }

    sql = SQL_DELETE_NOT_FISINED_ORDER;
    ps = prepareStatement(sql);
    try {
      ps.setLong(1, notFinishedOrderExpires.getEpochSecond());
      sum += ps.executeUpdate();
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
    return sum;
  }

  private static void addChallengesToValidate(List<ChallId> res, List<AcmeAuthz> authzs) {
    for (AcmeAuthz authz : authzs) {
      if (authz.getStatus() == AuthzStatus.pending) {
        for (AcmeChallenge challenge : authz.getChallenges()) {
          if (challenge.getStatus() == ChallengeStatus.processing) {
            res.add(new ChallId(authz.getId(), challenge.getSubId()));
            break;
          }
        }
      }
    }
  }

  private static long extractNotAfter(byte[] certBytes) {
    try {
      BufferedInputStream instream = new BufferedInputStream(new ByteArrayInputStream(certBytes));
      // SEQUENCE of Certificate
      Asn1StreamParser.skipTagLen(instream);

      // SEQUENCE OF TBSCertificate
      Asn1StreamParser.skipTagLen(instream);

      // #num = 4: version, serialNumber, signature, issuer
      int numFields = 4;
      for (int i = 0; i < numFields; i++) {
        Asn1StreamParser.skipField(instream);
      }

      // Validity
      Asn1StreamParser.skipTagLen(instream);

      // notBefore
      Asn1StreamParser.skipField(instream);

      // notAfter
      Instant notAfter = Asn1StreamParser.readTime(new Asn1StreamParser.MyInt(), instream, "notAfter");
      return notAfter.getEpochSecond();
    } catch (Exception ex) {
      throw new AcmeSystemException("certificate is invalid, should not happen");
    }
  }

}
