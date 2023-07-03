// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import java.util.Iterator;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public interface AcmeRepo {

  // set also the label
  void addAccount(AcmeAccount account);

  AcmeAccount getAccount(String label);

  AcmeAccount getAccountForJwk(Map<String, String> jwk);

  AcmeAccount keyChange(String accountLabel, Map<String, String> newJwk);

  void addOrder(String accountLabel, AcmeOrder order);

  AcmeOrder getOrder(String label);

  AcmeChallenge getChallenge(String label);

  AcmeAuthz getAuthz(String label);

  AcmeOrder[] getOrders(String accountLabel);

  Iterator<String> getOrdersToValidate();

  Iterator<String> getOrdersToEnroll();

}
