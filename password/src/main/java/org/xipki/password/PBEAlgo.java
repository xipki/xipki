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

package org.xipki.password;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public enum PBEAlgo {

    PBEWithHmacSHA256AndAES_256(1, "PBEWithHmacSHA256AndAES_256");

    private int code;

    private String algoName;

    private PBEAlgo(int code, String algoName) {
        this.code = code;
        this.algoName = algoName;
    }

    public int code() {
        return code;
    }

    public String algoName() {
        return algoName;
    }

    public static PBEAlgo forCode(int code) {
        for (PBEAlgo value : values()) {
            if (value.code == code) {
                return value;
            }
        }

        return null;
    }

}

