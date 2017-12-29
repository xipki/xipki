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

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionControl {

    private final boolean critical;

    private final boolean required;

    private final boolean request;

    public ExtensionControl(boolean critical, boolean required, boolean request) {
        this.critical = critical;
        this.required = required;
        this.request = request;
    }

    public boolean isCritical() {
        return critical;
    }

    public boolean isRequired() {
        return required;
    }

    public boolean isRequest() {
        return request;
    }

}
