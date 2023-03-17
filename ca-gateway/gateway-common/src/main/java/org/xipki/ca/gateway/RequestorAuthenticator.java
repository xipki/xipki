// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.security.X509Cert;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public interface RequestorAuthenticator {

  Requestor getPasswordRequestorByKeyId(byte[] keyId);

  Requestor getPasswordRequestorByUser(String user);

  Requestor getCertRequestor(X509Cert cert);

}
