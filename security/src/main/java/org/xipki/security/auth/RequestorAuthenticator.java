// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.auth;

import org.xipki.security.pkix.X509Cert;

/**
 *
 * @author Lijun Liao (xipki)
 */
public interface RequestorAuthenticator {

  /**
   * Return the password-based requestor for given keyID. Used for CMP gateway.
   * @param keyId the key ID
   * @return the requestor.
   */
  Requestor.SimplePasswordRequestor getSimplePasswordRequestorByKeyId(
      byte[] keyId);

  /**
   * Return the password-based requestor for given user. Used for EST, REST
   * and SCEP gateway.
   * @param user the user
   * @return the requestor.
   */
  Requestor.PasswordRequestor getPasswordRequestorByUser(String user);

  /**
   * Return the certificate-based requestor for given client certificate.
   * Used for CMP, EST, REST and SCEP gateway.
   * @param cert the client certificate
   * @return the requestor.
   */
  Requestor.CertRequestor getCertRequestor(X509Cert cert);

}
