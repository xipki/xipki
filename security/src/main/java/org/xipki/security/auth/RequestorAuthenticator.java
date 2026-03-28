// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.auth;

import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;

/**
 * Requestor Authenticator interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface RequestorAuthenticator {

  void init(String conf) throws XiSecurityException;

  /**
   * Return the password-based requestor for given keyID. Used by CMP gateway.
   * @param keyId the key ID
   * @return the requestor.
   */
  Requestor.SimplePasswordRequestor getSimplePasswordRequestorByKeyId(
      Requestor.Protocol protocol, byte[] keyId);

  /**
   * Return the password-based requestor for given user. Used by EST, REST
   * and SCEP gateway.
   * @param user the user
   * @return the requestor.
   */
  Requestor.PasswordRequestor getPasswordRequestorByUser(Requestor.Protocol protocol, String user);

  /**
   * Return the certificate-based requestor for given client certificate.
   * Used for CMP, EST, REST and SCEP gateway.
   * @param cert the client certificate
   * @return the requestor.
   */
  Requestor.CertRequestor getCertRequestor(Requestor.Protocol protocol, X509Cert cert);

}
