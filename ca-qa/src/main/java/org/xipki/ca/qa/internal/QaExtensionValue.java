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

package org.xipki.ca.qa.internal;

import java.util.Arrays;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaExtensionValue {

    private final boolean critical;

    private final byte[] value;

    public QaExtensionValue(final boolean critical, final byte[] value) {
        ParamUtil.requireNonNull("value", value);
        this.critical = critical;
        this.value = Arrays.copyOf(value, value.length);
    }

    public boolean isCritical() {
        return critical;
    }

    public byte[] value() {
        return Arrays.copyOf(value, value.length);
    }

}
