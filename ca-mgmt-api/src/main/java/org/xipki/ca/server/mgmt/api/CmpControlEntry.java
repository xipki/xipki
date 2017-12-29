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

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpControlEntry {

    private final String name;

    private final String conf;

    private boolean faulty;

    public CmpControlEntry(String name, String conf) {
        this.name = ParamUtil.requireNonBlank("name", name).toUpperCase();
        this.conf = ParamUtil.requireNonBlank("conf", conf);
    }

    public boolean isFaulty() {
        return faulty;
    }

    public void setFaulty(boolean faulty) {
        this.faulty = faulty;
    }

    public String name() {
        return name;
    }

    public String conf() {
        return conf;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("name: ").append(name).append('\n');
        sb.append("faulty: ").append(faulty).append('\n');
        sb.append("conf: ").append(conf);

        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CmpControlEntry)) {
            return false;
        }

        CmpControlEntry objB = (CmpControlEntry) obj;
        return name.equals(objB.name) && conf.equals(objB.conf);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
