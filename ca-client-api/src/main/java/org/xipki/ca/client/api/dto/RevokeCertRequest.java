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

package org.xipki.ca.client.api.dto;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeCertRequest {

    private final List<RevokeCertRequestEntry> requestEntries = new LinkedList<>();

    public boolean addRequestEntry(final RevokeCertRequestEntry requestEntry) {
        ParamUtil.requireNonNull("requestEntry", requestEntry);
        for (RevokeCertRequestEntry re : requestEntries) {
            if (re.id().equals(requestEntry.id())) {
                return false;
            }
        }

        requestEntries.add(requestEntry);
        return true;
    }

    public List<RevokeCertRequestEntry> requestEntries() {
        return Collections.unmodifiableList(requestEntries);
    }

}
