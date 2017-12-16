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

package org.xipki.ca.certprofile.commonpki;

import java.util.regex.Pattern;

/**
 * @author Lijun Liao
 * @since 2.0.1
 */

public class RegistrationNumberOption {

    private final Pattern regex;

    private final String constant;

    public RegistrationNumberOption(final String regex, final String constant) {
        if (regex != null) {
            if (constant != null) {
                throw new IllegalArgumentException(
                        "exactly one of regex and constant must be non null");
            }
            this.regex = Pattern.compile(regex);
            this.constant = null;
        } else {
            if (constant == null) {
                throw new IllegalArgumentException(
                        "exactly one of regex and constant must be non null");
            }
            this.regex = null;
            this.constant = constant;
        }
    }

    public Pattern regex() {
        return regex;
    }

    public String constant() {
        return constant;
    }

}
