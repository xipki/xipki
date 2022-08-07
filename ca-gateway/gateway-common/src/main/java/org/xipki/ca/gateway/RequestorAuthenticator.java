package org.xipki.ca.gateway;

import org.xipki.security.X509Cert;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public interface RequestorAuthenticator {

  Requestor getPasswordRequestorByKeyId(byte[] keyId);

  Requestor getPasswordRequestorByUser(String user);

  Requestor getCertRequestor(X509Cert cert);

}
