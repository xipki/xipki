// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Interface to check whether given algorithm is permitted.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public interface AlgorithmValidator {

  boolean isAlgorithmPermitted(AlgorithmIdentifier algId);

  boolean isAlgorithmPermitted(SignAlgo algo);

}
