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

package org.xipki.ca.certprofile.xijson;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.1
 */

public class SubjectDirectoryAttributesControl {

  private final List<ASN1ObjectIdentifier> types;

  public SubjectDirectoryAttributesControl(List<ASN1ObjectIdentifier> types) {
    Args.notEmpty(types, "types");
    this.types = new ArrayList<>(types);
  }

  public List<ASN1ObjectIdentifier> getTypes() {
    return types;
  }

}
