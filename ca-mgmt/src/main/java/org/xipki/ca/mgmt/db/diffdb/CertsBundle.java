// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Container of the map of serial number to digest value of certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CertsBundle {

  private final Map<BigInteger, DigestEntry> certs;

  private final List<BigInteger> serialNumbers;

  public CertsBundle(Map<BigInteger, DigestEntry> certs,
                     List<BigInteger> serialNumbers) {
    this.certs = Args.notEmpty(certs, "certs");
    this.serialNumbers = Args.notEmpty(serialNumbers, "serialNumbers");
  }

  public Map<BigInteger, DigestEntry> getCerts() {
    return certs;
  }

  public List<BigInteger> getSerialNumbers() {
    return serialNumbers;
  }

}
