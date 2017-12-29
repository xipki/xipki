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
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PublisherEntry {

    private final NameId ident;

    private final String type;

    private final String conf;

    private boolean faulty;

    public PublisherEntry(NameId ident, String type, String conf) {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        this.type = ParamUtil.requireNonBlank("type", type);
        this.conf = conf;
    }

    public NameId ident() {
        return ident;
    }

    public String type() {
        return type;
    }

    public String conf() {
        return conf;
    }

    public boolean isFaulty() {
        return faulty;
    }

    public void setFaulty(boolean faulty) {
        this.faulty = faulty;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("id: ").append(ident.id()).append('\n');
        sb.append("name: ").append(ident.name()).append('\n');
        sb.append("faulty: ").append(faulty).append('\n');
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ").append(conf);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PublisherEntry)) {
            return false;
        }

        PublisherEntry objB = (PublisherEntry) obj;
        if (!ident.equals(objB.ident)) {
            return false;
        }

        if (!type.equals(objB.type)) {
            return false;
        }

        if (!CompareUtil.equalsObject(conf, objB.conf)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return ident.hashCode();
    }

}
