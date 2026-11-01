// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.xipki.ca.gateway.dns.DnsException;
import org.xipki.ca.gateway.dns.DnsException.Reason;

/**
 * Limits the work of one validation (one TXT lookup including CNAMEs), as protection
 * against KeyTrap-like attacks (CVE-2023-50387).
 *
 * @author Lijun Liao (xipki)
 */
public final class ValidationBudget {

  public static final int DEFAULT_MAX_QUERIES = 30;

  public static final int DEFAULT_MAX_VERIFICATIONS = 32;

  public static final long DEFAULT_MAX_MILLIS = 30_000;

  private final long deadline;

  private int queries;

  private int verifications;

  public ValidationBudget() {
    this(DEFAULT_MAX_QUERIES, DEFAULT_MAX_VERIFICATIONS, DEFAULT_MAX_MILLIS);
  }

  public ValidationBudget(int maxQueries, int maxVerifications, long maxMillis) {
    this.queries = maxQueries;
    this.verifications = maxVerifications;
    this.deadline = System.currentTimeMillis() + maxMillis;
  }

  /**
   * Consumes one query.
   *
   * @throws DnsException if the budget is exhausted.
   */
  public void countQuery() throws DnsException {
    checkTime();
    if (--queries < 0) {
      throw new DnsException(Reason.LIMIT_EXCEEDED, "too many DNS queries");
    }
  }

  void countVerification() throws DnsException {
    checkTime();
    if (--verifications < 0) {
      throw new DnsException(Reason.LIMIT_EXCEEDED, "too many signature verifications");
    }
  }

  private void checkTime() throws DnsException {
    if (System.currentTimeMillis() > deadline) {
      throw new DnsException(Reason.LIMIT_EXCEEDED, "validation took too long");
    }
  }

}
