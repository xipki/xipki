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

package org.xipki.ca.server.mgmt.api;

import org.xipki.ca.api.NameId;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AddUserEntry {

    private final NameId ident;

    private final boolean active;

    private final String password;

    public AddUserEntry(NameId ident, boolean active, String password) throws CaMgmtException {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        this.active = active;
        this.password = ParamUtil.requireNonBlank("password", password);
    }

    public NameId ident() {
        return ident;
    }

    public boolean isActive() {
        return active;
    }

    public String password() {
        return password;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("id: ").append(ident.id()).append('\n');
        sb.append("name: ").append(ident.name()).append('\n');
        sb.append("active: ").append(active).append('\n');
        sb.append("password: ").append(password).append("\n");
        return sb.toString();
    }

}
