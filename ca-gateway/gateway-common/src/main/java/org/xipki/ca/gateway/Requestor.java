// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.security.X509Cert;

/**
 * Requestor info interface.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public interface Requestor {

  String getName();

  char[] getPassword();

  byte[] getKeyId();

  X509Cert getCert();

  boolean authenticate(char[] password);

  boolean authenticate(byte[] password);

  boolean isCertprofilePermitted(String certprofile);

  boolean isPermitted(int permission);

}
