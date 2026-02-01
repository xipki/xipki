// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.CertprofileException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Container of extension value control.
 *
 * @author Lijun Liao (xipki)
 */

public class ExtensionValues {

  private final Map<ASN1ObjectIdentifier, ExtensionValue> extensions =
      new HashMap<>();

  public void addExtension(ASN1ObjectIdentifier type, ExtensionValue value)
      throws CertprofileException {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      throw new CertprofileException("Extension " + type.getId() + " exists");
    }
    extensions.put(type, value);
  } // method addExtension

  public Set<ASN1ObjectIdentifier> getExtensionTypes() {
    return Collections.unmodifiableSet(extensions.keySet());
  }

  public ExtensionValue getExtensionValue(ASN1ObjectIdentifier type) {
    return extensions.get(Args.notNull(type, "type"));
  }

  public ExtensionValue removeExtensionValue(ASN1ObjectIdentifier type) {
    return extensions.remove(Args.notNull(type, "type"));
  }

  public int size() {
    return extensions.size();
  }

}
