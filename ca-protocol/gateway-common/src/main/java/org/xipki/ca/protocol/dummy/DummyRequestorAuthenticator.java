package org.xipki.ca.protocol.dummy;

import org.xipki.ca.protocol.Requestor;
import org.xipki.ca.protocol.RequestorAuthenticator;
import org.xipki.security.X509Cert;

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
