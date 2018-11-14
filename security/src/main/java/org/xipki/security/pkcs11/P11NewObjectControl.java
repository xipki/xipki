/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security.pkcs11;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P11NewObjectControl {

  private final byte[] id;

  private final String label;

  public P11NewObjectControl(byte[] id, String label) {
    this.id = id;
    this.label = Args.notBlank(label, "label");
  }

  public byte[] getId() {
    return id;
  }

  public String getLabel() {
    return label;
  }

}
