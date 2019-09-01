/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;

/**
 * Container of extension value control.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionValues {

  private final Map<ASN1ObjectIdentifier, ExtensionValue> extensions = new HashMap<>();

  public boolean addExtension(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value) {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      return false;
    }
    extensions.put(type, new ExtensionValue(critical, value));
    return true;
  } // method addExtension

  public boolean addExtension(ASN1ObjectIdentifier type, ExtensionValue value) {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      return false;
    }
    extensions.put(type, value);
    return true;
  } // method addExtension

  public Set<ASN1ObjectIdentifier> getExtensionTypes() {
    return Collections.unmodifiableSet(extensions.keySet());
  }

  public ExtensionValue getExtensionValue(ASN1ObjectIdentifier type) {
    return extensions.get(Args.notNull(type, "type"));
  }

  public boolean removeExtensionTuple(ASN1ObjectIdentifier type) {
    return extensions.remove(Args.notNull(type, "type")) != null;
  }

  public boolean containsExtension(ASN1ObjectIdentifier type) {
    return extensions.containsKey(Args.notNull(type, "type"));
  }

  public int size() {
    return extensions.size();
  }

}
