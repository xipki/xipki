// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.ca.sdk.jacob;

import org.xipki.ca.sdk.EncodeException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public interface CborEncodable {

  void encode(CborEncoder encoder) throws EncodeException;

}
