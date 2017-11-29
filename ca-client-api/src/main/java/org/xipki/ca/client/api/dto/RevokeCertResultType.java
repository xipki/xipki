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

import java.util.ArrayList;
import java.util.List;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeCertResultType {

    private List<ResultEntry> resultEntries;

    public List<ResultEntry> resultEntries() {
        return resultEntries;
    }

    public void addResultEntry(final ResultEntry resultEntry) {
        ParamUtil.requireNonNull("resultEntry", resultEntry);
        if (!(resultEntry instanceof RevokeCertResultEntry
                || resultEntry instanceof ErrorResultEntry)) {
            throw new IllegalArgumentException("unaccepted parameter of class "
                    + resultEntry.getClass().getName());
        }

        if (resultEntries == null) {
            resultEntries = new ArrayList<>(1);
        }

        resultEntries.add(resultEntry);
    }

}
