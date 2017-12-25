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

public enum CaStatus {

    ACTIVE("active"),
    INACTIVE("inactive");

    private String status;

    CaStatus(final String status) {
        this.status = status;
    }

    public String status() {
        return status;
    }

    public static CaStatus forName(final String status) {
        ParamUtil.requireNonNull("status", status);
        for (CaStatus value : values()) {
            if (value.status.equalsIgnoreCase(status)) {
                return value;
            }
        }

        throw new IllegalArgumentException("invalid CaStatus " + status);
    }

}
