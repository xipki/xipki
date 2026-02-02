// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.verify;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.SignAlgo;

/**
 * Interface to check whether given algorithm is permitted.
 *
 * @author Lijun Liao (xipki)
 */
public interface AlgorithmValidator {

  boolean isAlgorithmPermitted(AlgorithmIdentifier algId);

  boolean isAlgorithmPermitted(SignAlgo algo);

}
