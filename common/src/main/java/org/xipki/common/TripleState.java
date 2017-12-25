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

package org.xipki.common;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum TripleState {

    REQUIRED("required"),
    OPTIONAL("optional"),
    FORBIDDEN("forbidden");
    private final String value;

    TripleState(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static TripleState forValue(String textValue) {
        ParamUtil.requireNonNull("textValue", textValue);

        for (TripleState ts : TripleState.values()) {
            if (ts.value.equalsIgnoreCase(textValue)) {
                return ts;
            }
        }
        throw new IllegalArgumentException("invalid TripleState " + textValue);
    }

}
