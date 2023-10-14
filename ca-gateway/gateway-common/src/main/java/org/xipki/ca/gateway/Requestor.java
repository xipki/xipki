// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.security.X509Cert;

/**
 * Requestor interface.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public interface Requestor {

  /**
   * Returns the name of this requestor. Will not be used internally for any authentication. Only used
   * for internal logging.
   * @return the name of this requestor.
   */
  String getName();

  /**
   * Returns whether the requested certificate profile for given CA is allowed.
   * @param certprofile the certprofile name.
   * @param caName the CA name.
   * @return true if allowed, false otherwise.
   */
  boolean isCertprofilePermitted(String caName, String certprofile);

  /**
   * Returns whether the requested permissions is allowed.
   * @param permissions the permissions. Defined in {@link org.xipki.util.PermissionConstants},
   *                   can be combined value of multiple permissions.
   * @return true if all requested permissions are allowed, false otherwise.
   */
  boolean isPermitted(int permissions);

  /**
   * Password-based requestor interface. Used for EST, REST and SCEP gateway.
   *
   * @author Lijun Liao (xipki)
   * @since 6.4.0
   */
  interface PasswordRequestor extends Requestor {

    boolean authenticate(char[] password);

    boolean authenticate(byte[] password);

  }

  /**
   * Simple password-based requestor interface, used for the CMP gateway.
   *
   * @author Lijun Liao (xipki)
   * @since 6.4.0
   */
  interface SimplePasswordRequestor extends Requestor {

    byte[] getKeyId();

    char[] getPassword();

  }

  /**
   * Certificate-based requestor interface.
   *
   * @author Lijun Liao (xipki)
   * @since 6.4.0
   */

  interface CertRequestor extends Requestor {

    byte[] getKeyId();

    X509Cert getCert();

  }

}
