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

package org.xipki.ca.client.api;

import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertprofileInfo {

    private final String name;

    private final String type;

    private final String conf;

    public CertprofileInfo(final String name, final String type, final String conf) {
        this.name = ParamUtil.requireNonBlank("name", name).toUpperCase();
        this.type = StringUtil.isBlank(type) ? null : type;
        this.conf = StringUtil.isBlank(conf) ? null : conf;
    }

    public String name() {
        return name;
    }

    public String type() {
        return type;
    }

    public String conf() {
        return conf;
    }

}
