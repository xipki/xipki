// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.misc.LruCache;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeRepo implements AcmeDataSource.IdChecker {

  static class ListIterator <T> implements Iterator<T> {

    private final List<T> list;
    private final AtomicInteger index = new AtomicInteger(0);

    ListIterator(List<T> list) {
      this.list = list;
    }

    @Override
    public boolean hasNext() {
      return index.get() < list.size();
    }

    @Override
    public T next() {
      if (hasNext()) {
        return list.get(index.getAndIncrement());
      } else {
        return null;
      }
    }
  }

  private static class AccountLruCache extends LruCache<Long, AcmeAccount> {

    /**
     * Constructor with the maximal size.
     *
     * @param maxSize
     *        for caches that do not override {@link #sizeOf}, this is
     *        the maximum number of entries in the cache. For all other caches,
     *        this is the maximum sum of the sizes of the entries in this cache.
     */
    public AccountLruCache(int maxSize) {
      super(maxSize);
    }

    @Override
    protected void entryRemoved(boolean evicted, Long key,
                                AcmeAccount oldValue, AcmeAccount newValue) {
      super.entryRemoved(evicted, key, oldValue, newValue);
      if (oldValue != null) {
        try {
          oldValue.flush();
        } catch (Throwable th) {
          LogUtil.error(LOG, th,
              "error flushing AcmeAccount " + oldValue.id());
        }
      }
    }

  }

  private static class OrderLruCache extends LruCache<Long, AcmeOrder> {

    /**
     * Constructor with the maximal size.
     *
     * @param maxSize
     *        for caches that do not override {@link #sizeOf}, this is
     *        the maximum number of entries in the cache. For all other caches,
     *        this is the maximum sum of the sizes of the entries in this cache.
     */
    public OrderLruCache(int maxSize) {
      super(maxSize);
    }

    @Override
    protected void entryRemoved(boolean evicted, Long key,
                                AcmeOrder oldValue, AcmeOrder newValue) {
      super.entryRemoved(evicted, key, oldValue, newValue);
      if (oldValue != null) {
        try {
          oldValue.flush();
        } catch (Throwable th) {
          LogUtil.error(LOG, th,
              "error flushing AcmeOrder " + oldValue.id());
        }
      }
    }

  }

  private class DataToDbWriter implements Runnable {

    @Override
    public void run() {
      while (!stopMe) {
        try {
          try {
            Thread.sleep(syncDbSeconds * 1000L); // sleep for syncDbSeconds.
          } catch (InterruptedException e) {
          }

          writeToDb();
        } catch (Throwable t) {
          LogUtil.error(LOG, t, "unexpected error");
        }
      }
    }

  }

  static class IdsForOrder {

    private final long orderId;

    private final int[] authzSubIds;

    private final int[] challSubIds;

    public IdsForOrder(long orderId, int[] authzSubIds, int[] challSubIds) {
      this.orderId = orderId;
      this.authzSubIds = authzSubIds;
      this.challSubIds = challSubIds;
    }

    public long orderId() {
      return orderId;
    }

    public int[] authzSubIds() {
      return authzSubIds;
    }

    public int[] challSubIds() {
      return challSubIds;
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(AcmeRepo.class);

  private final AccountLruCache accountCache;

  private final OrderLruCache orderCache;

  private final AcmeDataSource dataSource;

  private final int syncDbSeconds;

  private boolean stopMe;

  public AcmeRepo(AcmeDataSource dataSource, int cacheSize, int syncDbSeconds) {
    this.accountCache = new AccountLruCache(
        Args.min(cacheSize, "cacheSize", 1));
    this.orderCache   = new OrderLruCache(
        Args.min(cacheSize, "cacheSize", 1));
    this.syncDbSeconds = Args.min(syncDbSeconds, "syncDbSeconds", 1);
    this.dataSource = Args.notNull(dataSource, "dataSource");
    this.dataSource.setIdChecker(this);
  }

  @Override
  public boolean accountIdExists(long id) {
    return accountCache.containsKey(id);
  }

  @Override
  public boolean orderIdExists(long id) {
    return orderCache.containsKey(id);
  }

  IdsForOrder newIdsForOrder(int numAuthzs, int numChalls)
      throws DataAccessException {
    return new IdsForOrder(dataSource.nextOrderId(),
        dataSource.nextAuthzIds(numAuthzs), dataSource.nextChallIds(numChalls));
  }

  public void start() {
    Thread t = new Thread(new DataToDbWriter());
    t.setName("dataToDbWriter");
    t.setDaemon(true);
    t.start();
  }

  public void addAccount(AcmeAccount account) {
    accountCache.put(account.id(), account);
    LOG.info("added account {}", account.idText());
  }

  public byte[] getCsr(long orderId) throws AcmeSystemException {
    AcmeOrder order = orderCache.get(orderId);
    if (order != null && order.csr() != null) {
      return order.csr();
    } else {
      return dataSource.getCsr(orderId);
    }
  }

  public AcmeAccount getAccount(long accountId) throws AcmeSystemException {
    AcmeAccount account = accountCache.get(accountId);
    if (account == null) {
      account = dataSource.getAccount(accountId);
      if (account != null) {
        accountCache.put(account.id(), account);
      }
    }
    return account;
  }

  public AcmeAccount getAccountForJwk(Map<String, String> jwk)
      throws AcmeSystemException {
    // from cache
    for (Map.Entry<Long, AcmeAccount> entry
        : accountCache.snapshot().entrySet()) {
      if (entry.getValue().hasJwk(jwk)) {
        return entry.getValue();
      }
    }

    AcmeAccount account = dataSource.getAccountForJwk(jwk);
    if (account != null) {
      accountCache.put(account.id(), account);
    }
    return account;
  }

  public void addOrder(AcmeOrder order) {
    // set IDs
    orderCache.put(order.id(), order);
    LOG.info("added order {}", order.idText());
  }

  public AcmeOrder getOrder(long orderId) throws AcmeSystemException {
    AcmeOrder order = orderCache.get(orderId);
    if (order == null) {
      order = dataSource.getOrder(orderId);
      if (order != null) {
        orderCache.put(order.id(), order);
      }
    }
    return order;
  }

  public AcmeOrder getOrderForCert(byte[] cert) throws AcmeSystemException {
    String sha256 = Base64.getUrlNoPaddingEncoder().encodeToString(
        HashAlgo.SHA256.hash(cert));
    // do not read CSR and CERT to save bandwidth.
    AcmeOrder order = null;
    for (Map.Entry<Long, AcmeOrder> entry : orderCache.snapshot().entrySet()) {
      if (sha256.equals(entry.getValue().getCertSha256())) {
        order = entry.getValue();
        break;
      }
    }

    if (order == null) {
      order = dataSource.getOrderForCertSha256(sha256);
      if (order != null) {
        orderCache.put(order.id(), order);
      }
    }

    return order;
  }

  public AcmeChallenge2 getChallenge(ChallId challId)
      throws AcmeSystemException {
    AcmeOrder order = getOrder(challId.orderId());
    if (order == null) {
      return null;
    }

    AcmeAuthz authz = order.getAuthz(challId.authzId());
    if (authz == null) {
      return null;
    }

    for (AcmeChallenge chall : authz.challenges()) {
      if (chall.subId() == challId.subId()) {
        return new AcmeChallenge2(chall, authz.identifier());
      }
    }

    return null;
  }

  public AcmeAuthz getAuthz(AuthzId authzId) throws AcmeSystemException {
    AcmeOrder order = getOrder(authzId.orderId());
    if (order == null) {
      return null;
    }

    return order.getAuthz(authzId.subId());
  }

  public List<Long> getOrderIds(long accountId) throws AcmeSystemException {
    List<Long> orderIds = new LinkedList<>();
    // from cache
    for (Map.Entry<Long, AcmeOrder> entry : orderCache.snapshot().entrySet()) {
      if (entry.getValue().accountId() == accountId) {
        orderIds.add(entry.getKey());
      }
    }

    // from database
    List<Long> dbOrderIds = dataSource.getOrderIds(accountId);
    orderIds.addAll(dbOrderIds);
    return orderIds;
  }

  public Iterator<ChallId> getChallengesToValidate()
      throws AcmeSystemException {
    // from database
    List<ChallId> dbIds = dataSource.getChallengesToValidate();
    List<ChallId> ids = new LinkedList<>(dbIds);

    // from cache
    for (Long id : orderCache.keySnapshot()) {
      AcmeOrder order = orderCache.get(id);
      if (order == null) {
        continue;
      }

      List<AcmeAuthz> authzs = order.authzs();
      if (authzs == null) {
        continue;
      }

      for (AcmeAuthz authz : authzs) {
        for (AcmeChallenge challenge : authz.challenges()) {
          ChallId challId = new ChallId(order.id(), authz.subId(),
              challenge.subId());
          boolean addMe = challenge.status() == ChallengeStatus.processing
              && authz.status() == AuthzStatus.pending
              && order.status() == OrderStatus.pending;

          if (addMe) {
            ids.add(challId);
            break;
          } else {
            ids.remove(challId);
          }
        } // end AcmeChallenge-for
      } // end AcmeAuthz-for
    }

    return new ListIterator<>(ids);
  }

  public Iterator<Long> getOrdersToEnroll() throws AcmeSystemException {
    // add those from database
    List<Long> dbIds = dataSource.getOrdersToEnroll();
    List<Long> ids = new LinkedList<>(dbIds);

    // from cache
    for (Long id : orderCache.keySnapshot()) {
      AcmeOrder order = orderCache.get(id);
      if (order == null) {
        continue;
      }

      order.updateStatus();

      if (order.status() == OrderStatus.processing) {
        if (!ids.contains(id)) {
          ids.add(id);
        }
      } else {
        ids.remove(id);
      }
    }

    return new ListIterator<>(ids);
  }

  public int cleanOrders(Instant certNotAfter, Instant notFinishedOrderExpires)
      throws AcmeSystemException {
    return dataSource.cleanOrders(certNotAfter, notFinishedOrderExpires);
  }

  public AcmeOrder newAcmeOrder(long accountId, long orderId) {
    return new AcmeOrder(accountId, orderId, dataSource);
  }

  public AcmeAccount newAcmeAccount() throws DataAccessException {
    return new AcmeAccount(dataSource.nextAccountId(), dataSource);
  }

  public void close() {
    stopMe = true;
    try {
      writeToDb();
    } catch (Exception e) {
      LogUtil.error(LOG, e, "error closing AcmeRepo.");
    }
  }

  private synchronized void writeToDb() throws AcmeSystemException {
    // save the accounts and orders
    for (Map.Entry<Long, AcmeAccount> account
        : accountCache.snapshot().entrySet()) {
      account.getValue().flush();
    }

    // save the accounts and orders
    for (Map.Entry<Long, AcmeOrder> order : orderCache.snapshot().entrySet()) {
      order.getValue().flush();
    }
  }

  public synchronized void flushOrderIfNotCached(AcmeOrder order)
      throws AcmeSystemException {
    AcmeOrder cachedOrder = orderCache.get(order.id());
    if (cachedOrder != order) {
      order.flush();
    }
  }

}
