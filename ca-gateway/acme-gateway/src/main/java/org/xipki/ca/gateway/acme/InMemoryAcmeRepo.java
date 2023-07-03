// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.util.Base64Url;

import java.security.SecureRandom;
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
public class InMemoryAcmeRepo implements AcmeRepo {

  private static class ListIterator implements Iterator<String> {

    private final List<String> list;
    private final AtomicInteger index = new AtomicInteger(0);

    ListIterator(List<String> list) {
      this.list = list;
    }

    @Override
    public boolean hasNext() {
      return index.get() < list.size();
    }

    @Override
    public String next() {
      if (hasNext()) {
        return list.get(index.getAndIncrement());
      } else {
        return null;
      }
    }
  }

  private final int labelNumBytes = 12;

  private final SecureRandom rnd = new SecureRandom();

  private final ConcurrentHashMap<String, AcmeAccount> accountMap = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, AcmeOrder> orderMap = new ConcurrentHashMap<>();

  private final ConcurrentHashMap<String, String> orderLabelToAccountMap = new ConcurrentHashMap<>();

  private final ConcurrentHashMap<String, String> authzLabelToOrderMap = new ConcurrentHashMap<>();

  private final ConcurrentHashMap<String, String> challLabelToOrderMap = new ConcurrentHashMap<>();

  private String rndLabel() {
    byte[] nonce = new byte[labelNumBytes];
    rnd.nextBytes(nonce);
    return Base64Url.encodeToStringNoPadding(nonce);
  }

  @Override
  public void addAccount(AcmeAccount account) {
    String label = rndLabel();
    account.setLabel(label);
    accountMap.put(label, account);
  }

  @Override
  public AcmeAccount getAccount(String label) {
    return accountMap.get(label);
  }

  @Override
  public AcmeAccount getAccountForJwk(Map<String, String> jwk) {
    for (Map.Entry<String, AcmeAccount> entry : accountMap.entrySet()) {
      if (entry.getValue().hasJwk(jwk)) {
        return entry.getValue();
      }
    }
    return null;
  }

  @Override
  public AcmeAccount keyChange(String accountLabel, Map<String, String> newJwk) {
    AcmeAccount account = accountMap.get(accountLabel);
    account.setJwk(newJwk);
    return account;
  }

  @Override
  public void addOrder(String accountLabel, AcmeOrder order) {
    AcmeAccount account = accountMap.get(accountLabel);
    if (account == null) {
      throw new AcmeProtocolException("account is unknown");
    }

    // set labels
    String orderLabel = rndLabel();
    order.setLabel(orderLabel);

    for (AcmeAuthz authz : order.getAuthzs()) {
      String authzLabel = rndLabel();
      authz.setLabel(authzLabel);
      authzLabelToOrderMap.put(authzLabel, orderLabel);

      for (AcmeChallenge chall : authz.getChallenges()) {
        String challLabel = rndLabel();
        chall.setLabel(challLabel);
        challLabelToOrderMap.put(challLabel, orderLabel);
      }
    }

    orderMap.put(orderLabel, order);
    orderLabelToAccountMap.put(orderLabel, accountLabel);
  }

  @Override
  public AcmeOrder getOrder(String label) {
    return orderMap.get(label);
  }

  @Override
  public AcmeChallenge getChallenge(String label) {
    String orderLabel = challLabelToOrderMap.get(label);
    if (orderLabel == null) {
      return null;
    }

    AcmeOrder order = orderMap.get(orderLabel);
    for (AcmeAuthz authz : order.getAuthzs()) {
      for (AcmeChallenge chall : authz.getChallenges()) {
        if (chall.getLabel().equals(label)) {
          return chall;
        }
      }
    }

    return null;
  }

  @Override
  public AcmeAuthz getAuthz(String label) {
    String orderLabel = authzLabelToOrderMap.get(label);
    if (orderLabel == null) {
      return null;
    }

    AcmeOrder order = orderMap.get(orderLabel);
    return order.getAuthz(label);
  }

  @Override
  public AcmeOrder[] getOrders(String accountLabel) {
    // TODO: optimize
    List<String> orderLabels = new LinkedList<>();
    for (Map.Entry<String, String> entry : orderLabelToAccountMap.entrySet()) {
      if (entry.getValue().equals(accountLabel)) {
        orderLabels.add(entry.getKey());
      }
    }

    AcmeOrder[] orders = new AcmeOrder[orderLabels.size()];
    for (int i = 0; i < orderLabels.size(); i++) {
      orders[i] = orderMap.get(orderLabels.get(i));
    }
    return orders;
  }

  @Override
  public Iterator<String> getOrdersToValidate() {
    List<String> labels =  new LinkedList<>();
    for (String label : orderMap.keySet()) {
      AcmeOrder order = orderMap.get(label);
      OrderStatus status = order.getStatus();
      if (status != OrderStatus.pending) {
        continue;
      }

      boolean toValidate = false;
      for (AcmeAuthz authz : order.getAuthzs()) {
        if (authz.getStatus() == AuthzStatus.pending) {
          for (AcmeChallenge challenge : authz.getChallenges()) {
            if (challenge.getStatus() == ChallengeStatus.processing) {
              toValidate = true;
              break;
            }
          }
        }

        if (toValidate) {
          break;
        }
      }

      if (toValidate) {
        labels.add(label);
      }
    }
    return new ListIterator(labels);
  }

  @Override
  public Iterator<String> getOrdersToEnroll() {
    List<String> labels =  new LinkedList<>();
    for (String label : orderMap.keySet()) {
      AcmeOrder order = orderMap.get(label);
      if (order.getStatus() == OrderStatus.processing) {
        labels.add(label);
      }
    }
    return new ListIterator(labels);
  }

}
