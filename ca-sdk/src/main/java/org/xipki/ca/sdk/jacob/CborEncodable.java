package org.xipki.ca.sdk.jacob;

import org.xipki.ca.sdk.EncodeException;

public interface CborEncodable {

  void encode(CborEncoder encoder) throws EncodeException;

}
