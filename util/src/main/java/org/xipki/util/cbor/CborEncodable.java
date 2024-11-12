// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.cbor;

import org.xipki.util.exception.EncodeException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public interface CborEncodable {

  void encode(CborEncoder encoder) throws EncodeException;

}
