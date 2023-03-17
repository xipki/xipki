// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dummy;

import org.xipki.ca.gateway.Requestor;
import org.xipki.ca.gateway.RequestorAuthenticator;
import org.xipki.security.X509Cert;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class DummyRequestorAuthenticator implements RequestorAuthenticator {
  @Override
  public Requestor getPasswordRequestorByKeyId(byte[] keyId) {
    return DummyPasswordRequestor.ofKeyId(keyId);
  }

  @Override
  public Requestor getPasswordRequestorByUser(String user) {
    return DummyPasswordRequestor.ofUser(user);
  }

  @Override
  public Requestor getCertRequestor(X509Cert cert) {
    return new DummyCertRequestor(cert);
  }
}
