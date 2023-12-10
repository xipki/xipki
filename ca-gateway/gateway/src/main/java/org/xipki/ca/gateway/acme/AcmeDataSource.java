// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.type.*;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;
import org.xipki.util.CompareUtil;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeDataSource {

  public interface IdChecker {

    boolean accountIdExists(long id);

    boolean orderIdExists(long id);

  }

  private static final String SQL_ADD_ACCOUNT =
      "INSERT INTO ACCOUNT (ID,LUPDATE,STATUS,JWK_SHA256,DATA) VALUES (?,?,?,?,?)";

  private static final String SQL_ADD_ORDER = "INSERT INTO ORDER2 (ID,LUPDATE,ACCOUNT_ID,STATUS,EXPIRES," +
      "CERT_NAFTER,CERT_SHA256,CERTREQ_META,CSR,CERT,AUTHZS) VALUES (?,?,?,?,?,?,?,?,?,?,?)";

  private static final String SQL_DELETE_ORDER_CERT_EXPIRED = "DELETE FROM ORDER2 WHERE CERT_NAFTER<?";

  private static final String SQL_DELETE_NOT_FINISHED_ORDER = "DELETE FROM ORDER2 WHERE " +
      "STATUS != " + OrderStatus.valid.getCode() + " AND EXPIRES<?";

  private static final String SQL_SELECT_ORDER_ID = "SELECT ID FROM ORDER2 WHERE ACCOUNT=?";

  private static final Logger LOG = LoggerFactory.getLogger(AcmeDataSource.class);

  private final String sqlGetAccount;

  private final String sqlGetAccountFowJwkSha256;

  private final String sqlGetOrderById;

  private final String sqlGetOrderByCertSha256;

  private final DataSourceWrapper dataSource;

  private final SecureRandom rnd = new SecureRandom();

  private IdChecker idChecker;

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

  public void setIdChecker(IdChecker idChecker) {
    this.idChecker = idChecker;
  }

  private PreparedStatement prepareStatement(String sql) throws AcmeSystemException {
    try {
      return dataSource.prepareStatement(sql);
    } catch (DataAccessException ex) {
      throw new AcmeSystemException(ex);
    }
  } // method prepareStatement

  public void addNewAccount(AcmeAccount account) throws AcmeSystemException {
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
      ps.setString(index, account.getData().encode());
      ps.executeUpdate();
      LOG.info("Database: added account " + account.getId());
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public byte[] getCert(long orderId) throws AcmeSystemException {
    try {
      String str = dataSource.getFirstStringValue(null, "ORDER2", "CERT", "ID=" + orderId);
      return str == null ? null : Base64Url.decodeFast(str);
    } catch (DataAccessException e) {
      throw new AcmeSystemException(e);
    }
  }

  public byte[] getCsr(long orderId) throws AcmeSystemException {
    try {
      String str = dataSource.getFirstStringValue(null, "ORDER2", "CSR", "ID=" + orderId);
      return str == null ? null : Base64Url.decodeFast(str);
    } catch (DataAccessException e) {
      throw new AcmeSystemException(e);
    }
  }

  public AcmeAccount getAccount(long accountId) throws AcmeSystemException {
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

  public void updateAccount(AcmeAccount oldAccount, AcmeAccount newAccount) throws AcmeSystemException {
    if (oldAccount.getId() != newAccount.getId()) {
      throw new IllegalArgumentException("oldAccount and newAccount does not have the same id");
    }

    boolean updateJwkFp = oldAccount.getJwkSha256().equals(newAccount.getJwkSha256());
    boolean updateStatus = oldAccount.getStatus() != newAccount.getStatus();
    String oldData = oldAccount.getData().encode();
    String newData = newAccount.getData().encode();
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
      LOG.info("Database: added account " + oldAccount.getId());
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public AcmeAccount getAccountForJwk(Map<String, String> jwk) throws AcmeSystemException {
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

  private AcmeAccount getAccount(PreparedStatement ps, String sql) throws AcmeSystemException {
    // ID,JWK_SHA256,STATUS,DATA FROM ACCOUNT
    ResultSet rs = null;
    try {
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      AccountStatus status = AccountStatus.ofCode(rs.getInt("STATUS"));
      AcmeAccount.Data data = AcmeAccount.Data.decode(rs.getString("DATA"));
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

  public void addNewOrder(AcmeOrder order) throws AcmeSystemException {
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
        ps.setLong(index++, X509Util.extractCertNotAfter(certBytes));
      }
      ps.setString(index++, order.getCertSha256());

      if (order.getCertReqMeta() == null) {
        ps.setNull(index, Types.VARCHAR);
      } else {
        ps.setString(index, order.getCertReqMeta().encode());
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

      ps.setString(index, order.getEncodedAuthzs());

      ps.executeUpdate();
      LOG.info("Database: added order " + order.getId());
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public void updateOrder(AcmeOrder oldOrder, AcmeOrder newOrder) throws AcmeSystemException {
    if (oldOrder.getId() != newOrder.getId()) {
      throw new IllegalArgumentException("oldOrder and newOrder does not have the same id");
    }

    if (oldOrder.getAccountId() != newOrder.getAccountId()) {
      throw new IllegalArgumentException("oldOrder and newOrder does not have the same account");
    }

    newOrder.updateStatus();

    // ACCOUNT_ID,STATUS,EXPIRES,CSR,AUTHZS
    boolean updateStatus = oldOrder.getStatus() != newOrder.getStatus();
    boolean updateExpires = !CompareUtil.equalsObject(oldOrder.getExpires(), newOrder.getExpires());
    boolean updateAuthzs = !CompareUtil.equalsObject(oldOrder.getAuthzs(), newOrder.getAuthzs());
    boolean updateCertReqMeta = !CompareUtil.equalsObject(oldOrder.getCertReqMeta(), newOrder.getCertReqMeta());
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
          ps.setString(index, newOrder.getEncodedAuthzs());
        }
        index++;
      }

      if (updateCertReqMeta) {
        if (newOrder.getCertReqMeta() == null) {
          ps.setNull(index, Types.VARCHAR);
        } else {
          ps.setString(index, newOrder.getCertReqMeta().encode());
        }
        index++;
      }

      if (updateCsr) {
        ps.setString(index++, Base64Url.encodeToStringNoPadding(newOrder.getCsr()));
      }

      if (updateCert) {
        byte[] certBytes = newOrder.getCert();
        ps.setLong(index++, X509Util.extractCertNotAfter(certBytes));
        ps.setString(index++, newOrder.getCertSha256());
        ps.setString(index, Base64Url.encodeToStringNoPadding(certBytes));
      }

      ps.executeUpdate();
      LOG.info("Database: updated order " + oldOrder.getId());
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
  }

  public AcmeOrder getOrder(long orderId) throws AcmeSystemException {
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

  public AcmeOrder getOrderForCertSha256(String certSha256) throws AcmeSystemException {
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
    long accountId = rs.getLong("ACCOUNT_ID");
    if (id == null) {
      id = rs.getLong("ID");
    }

    AcmeOrder order = new AcmeOrder(accountId, id, this);
    order.setInDb(true);
    order.setStatus(OrderStatus.ofCode(rs.getInt("STATUS")));
    order.setExpires(Instant.ofEpochSecond(rs.getLong("EXPIRES")));
    String str = rs.getString("CERTREQ_META");
    if (str != null) {
      order.setCertReqMeta(CertReqMeta.decode(str));
    }

    String authzsStr = rs.getString("AUTHZS");
    order.setAuthzs(AcmeAuthz.decodeAuthzs(authzsStr));

    return order;
  }

  public AcmeAuthz getAuthz(byte[] authzId) throws AcmeSystemException {
    AuthzId id = new AuthzId(authzId);
    AcmeOrder order = getOrder(id.getOrderId());
    if (order == null) {
      return null;
    }

    return order.getAuthz(id.getSubId());
  }

  public List<Long> getOrderIds(long accountId) throws AcmeSystemException {
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

  public List<ChallId> getChallengesToValidate() throws AcmeSystemException {
    final String sql = dataSource.buildSelectFirstSql(1000, "ID,AUTHZS FROM ORDER2 WHERE STATUS=?");
    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;
    try {
      ps.setInt(1, OrderStatus.pending.getCode());
      rs = ps.executeQuery();

      List<ChallId> ids =  new LinkedList<>();
      while (rs.next()) {
        List<AcmeAuthz> authzs = AcmeAuthz.decodeAuthzs(rs.getString("AUTHZS"));
        addChallengesToValidate(ids, rs.getLong("ID"), authzs);
      }
      return ids;
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }
  }

  public List<Long> getOrdersToEnroll() throws AcmeSystemException {
    // add those from database
    final String sql = dataSource.buildSelectFirstSql(1000, "ID FROM ORDER2 WHERE STATUS=?");
    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;
    try {
      ps.setInt(1, OrderStatus.processing.getCode());
      rs = ps.executeQuery();

      List<Long> ids =  new LinkedList<>();
      while (rs.next()) {
        ids.add(rs.getLong("ID"));
      }
      return ids;
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, rs);
    }
  }

  public int cleanOrders(Instant certNotAfter, Instant notFinishedOrderExpires) throws AcmeSystemException {
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

      LOG.info("Database: deleted orders with certificates expired before {}", certNotAfter);
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }

    sql = SQL_DELETE_NOT_FINISHED_ORDER;
    ps = prepareStatement(sql);
    try {
      ps.setLong(1, notFinishedOrderExpires.getEpochSecond());
      sum += ps.executeUpdate();
      LOG.info("Database: deleted orders expired before {}", certNotAfter);
    } catch (SQLException ex) {
      throw new AcmeSystemException(dataSource.translate(sql, ex));
    } finally {
      dataSource.releaseResources(ps, null);
    }
    return sum;
  }

  private static void addChallengesToValidate(List<ChallId> res, long orderId, List<AcmeAuthz> authzs) {
    for (AcmeAuthz authz : authzs) {
      if (authz.getStatus() != AuthzStatus.pending) {
        continue;
      }

      for (AcmeChallenge challenge : authz.getChallenges()) {
        if (challenge.getStatus() == ChallengeStatus.processing) {
          res.add(new ChallId(orderId, authz.getSubId(), challenge.getSubId()));
          break;
        }
      }
    }
  }

  public long nextAccountId() throws DataAccessException {
    while (true) {
      long id = rnd.nextLong();
      if (idChecker.accountIdExists(id)) {
        continue;
      }

      if (!dataSource.columnExists(null, "ACCOUNT", "ID", id)) {
        return id;
      }
    }
  }

  public long nextOrderId() throws DataAccessException {
    while (true) {
      long id = rnd.nextLong();
      if (idChecker.orderIdExists(id)) {
        continue;
      }

      if (!dataSource.columnExists(null, "ORDER2", "ID", id)) {
        return id;
      }
    }
  }

  public int[] nextAuthzIds(int numAuthzs) {
    return nextIntIds(numAuthzs);
  }

  public int[] nextChallIds(int numChalls) {
    return nextIntIds(numChalls);
  }

  private int[] nextIntIds(int num) {
    if (num == 1) {
      return new int[]{ rnd.nextInt() & 0xFFFF};
    }

    List<Integer> ids = new ArrayList<>(num);
    for (int i = 0; i < num; i++) {
      int id = rnd.nextInt() & 0xFFFF;
      while (ids.contains(id)) {
        id = rnd.nextInt() & 0xFFFF;
      }
      ids.add(id);
    }

    int[] ret = new int[num];
    for (int i = 0; i < num; i++) {
      ret[i] = ids.get(i);
    }
    return ret;
  }

}
