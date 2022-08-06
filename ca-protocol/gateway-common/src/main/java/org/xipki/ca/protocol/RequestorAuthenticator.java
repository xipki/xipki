package org.xipki.ca.protocol;

import org.xipki.security.X509Cert;

public interface RequestorAuthenticator {

  Requestor getPasswordRequestorByKeyId(byte[] keyId);

  Requestor getPasswordRequestorByUser(String user);

  Requestor getCertRequestor(X509Cert cert);

}
