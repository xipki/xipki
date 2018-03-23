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

package org.xipki.security.pkcs11.provider;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for SM2 ID parameter.
 *
 * @author Lijun Liao
 *
 */
public class XiSM2ParameterSpec implements AlgorithmParameterSpec {
  private byte[] id;

  /**
   * Base constructor.
   *
   * @param id the ID string associated with this usage of SM2.
   */
  public XiSM2ParameterSpec(byte[] id) {
    if (id == null) {
      throw new NullPointerException("id string cannot be null");
    }

    this.id = Arrays.clone(id);
  }

  /**
   * Return the ID value.
   *
   * @return the ID string.
   */
  public byte[] getId() {
    return Arrays.clone(id);
  }
}
