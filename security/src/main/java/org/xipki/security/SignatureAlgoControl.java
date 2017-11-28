/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignatureAlgoControl {

    private final boolean rsaMgf1;

    private final boolean dsaPlain;

    public SignatureAlgoControl() {
        this.rsaMgf1 = false;
        this.dsaPlain = false;
    }

    public SignatureAlgoControl(final boolean rsaMgf1, final boolean dsaPlain) {
        this.rsaMgf1 = rsaMgf1;
        this.dsaPlain = dsaPlain;
    }

    public boolean isRsaMgf1() {
        return rsaMgf1;
    }

    public boolean isDsaPlain() {
        return dsaPlain;
    }

}
