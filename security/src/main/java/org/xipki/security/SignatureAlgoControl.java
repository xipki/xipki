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

package org.xipki.security;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignatureAlgoControl {

  private final boolean rsaMgf1;

  private final boolean dsaPlain;

  private final boolean gm;

  public SignatureAlgoControl() {
    this(false, false, false);
  }

  public SignatureAlgoControl(boolean rsaMgf1, boolean dsaPlain) {
    this(rsaMgf1, dsaPlain, false);
  }

  public SignatureAlgoControl(boolean rsaMgf1, boolean dsaPlain, boolean gm) {
    this.rsaMgf1 = rsaMgf1;
    this.dsaPlain = dsaPlain;
    this.gm = gm;
  }

  public boolean isRsaMgf1() {
    return rsaMgf1;
  }

  public boolean isDsaPlain() {
    return dsaPlain;
  }

  public boolean isGm() {
    return gm;
  }

}
