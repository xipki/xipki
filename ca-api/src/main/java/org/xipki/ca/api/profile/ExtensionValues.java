// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;
import org.xipki.ca.api.CertprofileException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Extension Values.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionValues {

  private final Map<Asn1Oid, ExtensionValue> extensions = new HashMap<>();

  public void addExtension(Asn1Oid type, ExtensionValue value)
      throws CertprofileException {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      throw new CertprofileException("Extension " + type.getId() + " exists");
    }
    extensions.put(type, value);
  } // method addExtension

  public Set<Asn1Oid> getExtensionTypes() {
    return Collections.unmodifiableSet(extensions.keySet());
  }

  public ExtensionValue getExtensionValue(Asn1Oid type) {
    return extensions.get(Args.notNull(type, "type"));
  }

  public ExtensionValue removeExtensionValue(Asn1Oid type) {
    return extensions.remove(Args.notNull(type, "type"));
  }

  public int size() {
    return extensions.size();
  }

}
