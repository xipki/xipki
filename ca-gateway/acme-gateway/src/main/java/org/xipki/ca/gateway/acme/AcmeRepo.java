// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;
import org.xipki.util.LogUtil;
import org.xipki.util.LruCache;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeRepo {

  private static class ListIterator <T> implements Iterator<T> {

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
     * @param maxSize for caches that do not override {@link #sizeOf}, this is
     *                the maximum number of entries in the cache. For all other caches,
     *                this is the maximum sum of the sizes of the entries in this cache.
     */
    public AccountLruCache(int maxSize) {
      super(maxSize);
    }

    @Override
    protected void entryRemoved(boolean evicted, Long key, AcmeAccount oldValue, AcmeAccount newValue) {
      super.entryRemoved(evicted, key, oldValue, newValue);
    }

  }

  private static class OrderLruCache extends LruCache<Long, AcmeOrder> {

    /**
     * Constructor with the maximal size.
     *
     * @param maxSize for caches that do not override {@link #sizeOf}, this is
     *                the maximum number of entries in the cache. For all other caches,
     *                this is the maximum sum of the sizes of the entries in this cache.
     */
    public OrderLruCache(int maxSize) {
      super(maxSize);
    }

    @Override
    protected void entryRemoved(boolean evicted, Long key, AcmeOrder oldValue, AcmeOrder newValue) {
      super.entryRemoved(evicted, key, oldValue, newValue);
    }

  }

  private class DataToDbWriter implements Runnable {

    @Override
    public void run() {
      while (!stopMe) {
        try {
          try {
            Thread.sleep(syncDbSeconds * 1000); // sleep for syncDbSeconds.
          } catch (InterruptedException e) {
          }

          writeToDb();
        } catch (Throwable t) {
          LogUtil.error(LOG, t, "expected error");
        }
      }
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(AcmeRepo.class);

  private final SecureRandom rnd = new SecureRandom();

  private final AccountLruCache accountCache;

  private final OrderLruCache orderCache;

  private final ConcurrentHashMap<Long, Long> authzIdToOrderMap = new ConcurrentHashMap<>();

  private final AcmeDataSource dataSource;

  private final int syncDbSeconds;

  private boolean stopMe;

  public AcmeRepo(AcmeDataSource dataSource, int cacheSize, int syncDbSeconds) {
    this.accountCache = new AccountLruCache(Args.min(cacheSize, "cacheSize", 1));
    this.orderCache = new OrderLruCache(Args.min(cacheSize, "cacheSize", 1));
    this.syncDbSeconds = Args.min(syncDbSeconds, "syncDbSeconds", 1);
    this.dataSource = Args.notNull(dataSource, "dataSource");
  }

  public void start() {
    Thread t = new Thread(new DataToDbWriter());
    t.setName("dataToDbWriter");
    t.setDaemon(true);
    t.start();
  }

  private long rndId() {
    return rnd.nextLong();
  }

  public void addAccount(AcmeAccount account) {
    accountCache.put(account.getId(), account);
  }

  public byte[] getCert(long orderId) {
    AcmeOrder order = orderCache.get(orderId);
    if (order != null && order.getCert() != null) {
      return order.getCert();
    } else {
      return dataSource.getCert(orderId);
    }
  }

  public byte[] getCsr(long orderId) {
    AcmeOrder order = orderCache.get(orderId);
    if (order != null && order.getCsr() != null) {
      return order.getCsr();
    } else {
      return dataSource.getCsr(orderId);
    }
  }

  public AcmeAccount getAccount(long accountId) {
    AcmeAccount account = accountCache.get(accountId);
    if (account == null) {
      account = dataSource.getAccount(accountId);
    }
    return account;
  }

  public AcmeAccount getAccountForJwk(Map<String, String> jwk) {
    // from cache
    for (Map.Entry<Long, AcmeAccount> entry : accountCache.snapshot().entrySet()) {
      if (entry.getValue().hasJwk(jwk)) {
        return entry.getValue();
      }
    }

    return dataSource.getAccountForJwk(jwk);
  }

  public void addOrder(AcmeOrder order) {
    AcmeAccount account = getAccount(order.getAccountId());
    if (account == null) {
      throw new AcmeProtocolException("account is unknown");
    }

    // set IDs
    long orderId = order.getId();
    for (AcmeAuthz authz : order.getAuthzs()) {
      long authzId = rndId();
      authz.setId(authzId);
      authzIdToOrderMap.put(authzId, orderId);

      for (AcmeChallenge chall : authz.getChallenges()) {
        chall.setSubId(rnd.nextInt());
      }
    }

    orderCache.put(orderId, order);
  }

  public AcmeOrder getOrder(long orderId) {
    AcmeOrder order = orderCache.get(orderId);
    if (order == null) {
      order = dataSource.getOrder(orderId);
    }
    return order;
  }

  public AcmeOrder getOrderForCert(byte[] cert) {
    String sha256 = Base64Url.encodeToStringNoPadding(HashAlgo.SHA256.hash(cert));
    // do not read CSR and CERT to save bandwidth.
    AcmeOrder order = null;
    for (Map.Entry<Long, AcmeOrder> entry : orderCache.snapshot().entrySet()) {
      if (sha256.equals(entry.getValue().getCertSha256())) {
        order = entry.getValue();
        break;
      }
    }

    if (order == null) {
      return dataSource.getOrderForCertSha256(sha256);
    }
    return order;
  }

  public AcmeChallenge2 getChallenge(ChallId challId) {
    AcmeAuthz authz = getAuthz(challId.getAuthzId());
    if (authz != null) {
      for (AcmeChallenge chall : authz.getChallenges()) {
        if (chall.getSubId() == challId.getSubId()) {
          return new AcmeChallenge2(chall, authz.getIdentifier());
        }
      }
    }

    return null;
  }

  public AcmeAuthz getAuthz(long authzId) {
    // from cache
    Long orderId = authzIdToOrderMap.get(authzId);
    if (orderId != null) {
      AcmeOrder order = orderCache.get(orderId);
      if (order != null) {
        return order.getAuthz(authzId);
      }
    }

    return dataSource.getAuthz(authzId);
  }

  public List<Long> getOrderIds(long accountId) {
    List<Long> orderIds = new LinkedList<>();
    // from cache
    for (Map.Entry<Long, AcmeOrder> entry : orderCache.snapshot().entrySet()) {
      if (entry.getValue().getAccountId() == accountId) {
        orderIds.add(entry.getKey());
      }
    }

    // from database
    List<Long> dbOrderIds = dataSource.getOrderIds(accountId);
    orderIds.addAll(dbOrderIds);
    return orderIds;
  }

  public Iterator<ChallId> getChallengesToValidate() {
    List<ChallId> ids =  new LinkedList<>();
    // from cache
    for (Long id : orderCache.keySnapshot()) {
      AcmeOrder order = orderCache.get(id);
      if (order.getStatus() == OrderStatus.pending) {
        for (AcmeAuthz authz : order.getAuthzs()) {
          if (authz.getStatus() == AuthzStatus.pending) {
            for (AcmeChallenge challenge : authz.getChallenges()) {
              if (challenge.getStatus() == ChallengeStatus.processing) {
                ids.add(new ChallId(authz.getId(), challenge.getSubId()));
                break;
              }
            }
          }
        }

      }
    }

    // from database
    List<ChallId> dbIds = dataSource.getChallengesToValidate();
    ids.addAll(dbIds);

    return new ListIterator<>(ids);
  }

  public Iterator<Long> getOrdersToEnroll() {
    List<Long> ids =  new LinkedList<>();
    // from cache
    for (Long id : orderCache.keySnapshot()) {
      AcmeOrder order = orderCache.get(id);
      order.updateStatus();

      if (order.getStatus() == OrderStatus.processing) {
        ids.add(id);
      }
    }

    // add those from database
    List<Long> dbIds = dataSource.getOrdersToEnroll();
    ids.addAll(dbIds);
    return new ListIterator<>(ids);
  }

  public int cleanOrders(Instant certNotAfter, Instant notFinishedOrderExpires) {
    return dataSource.cleanOrders(certNotAfter, notFinishedOrderExpires);
  }

  public AcmeOrder newAcmeOrder(long accountId) {
    long orderId = rndId();
    return new AcmeOrder(orderId, accountId, dataSource);
  }

  public AcmeAccount newAcmeAccount() {
    long id = rndId();
    return new AcmeAccount(id, dataSource);
  }

  public void close() {
    stopMe = true;
    writeToDb();
  }

  private synchronized void writeToDb() {
    // save the accounts and orders
    for (Map.Entry<Long, AcmeAccount> account : accountCache.snapshot().entrySet()) {
      account.getValue().flush();
    }

    // save the accounts and orders
    for (Map.Entry<Long, AcmeOrder> order : orderCache.snapshot().entrySet()) {
      order.getValue().flush();
    }
  }

}
