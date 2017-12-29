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

package org.xipki.ca.dbtool.diffdb.io;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaEntryContainer {

    private final Map<Integer, CaEntry> caEntryMap;

    public CaEntryContainer(Set<CaEntry> caEntries) {
        ParamUtil.requireNonEmpty("caEntries", caEntries);
        caEntryMap = new HashMap<>(caEntries.size());
        for (CaEntry m : caEntries) {
            caEntryMap.put(m.caId(), m);
        }
    }

    public void addDigestEntry(int caId, long id, DbDigestEntry reportEntry)
            throws IOException, InvalidDataObjectException {
        CaEntry ce = caEntryMap.get(caId);
        if (ce == null) {
            throw new IllegalArgumentException("unknown caId '" + caId + "'");
        }
        ce.addDigestEntry(id, reportEntry);
    }

    public void close() throws IOException {
        StringBuilder sb = new StringBuilder();

        for (CaEntry m : caEntryMap.values()) {
            try {
                m.close();
            } catch (IOException ex) {
                sb.append("could not close CAEntry '").append(m.caId());
                sb.append("': ").append(ex.getMessage()).append(", ");
            }
        }

        int len = sb.length();
        if (len > 0) {
            sb.delete(len - 2, len);
            throw new IOException(sb.toString());
        }
    }

}
