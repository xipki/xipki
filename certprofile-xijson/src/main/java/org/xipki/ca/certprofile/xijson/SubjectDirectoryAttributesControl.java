// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * Control of SubjectDirectoryAttributes.
 *
 * @author Lijun Liao
 * @since 2.0.1
 */

public class SubjectDirectoryAttributesControl {

  private final List<ASN1ObjectIdentifier> types;

  public SubjectDirectoryAttributesControl(List<ASN1ObjectIdentifier> types) {
    this.types = new ArrayList<>(Args.notEmpty(types, "types"));
  }

  public List<ASN1ObjectIdentifier> getTypes() {
    return types;
  }

}
