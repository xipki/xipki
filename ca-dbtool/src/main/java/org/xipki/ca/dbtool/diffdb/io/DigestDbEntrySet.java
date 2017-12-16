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

package org.xipki.ca.dbtool.diffdb.io;

import java.util.LinkedList;
import java.util.List;

import org.xipki.common.QueueEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DigestDbEntrySet implements QueueEntry, Comparable<DigestDbEntrySet> {

    private final long startId;

    private Exception exception;

    private List<IdentifiedDbDigestEntry> entries = new LinkedList<>();

    public DigestDbEntrySet(final long startId) {
        this.startId = startId;
    }

    public void setException(final Exception exception) {
        this.exception = exception;
    }

    public Exception exception() {
        return exception;
    }

    public void addEntry(final IdentifiedDbDigestEntry entry) {
        entries.add(entry);
    }

    public long startId() {
        return startId;
    }

    public List<IdentifiedDbDigestEntry> entries() {
        return entries;
    }

    @Override
    public int compareTo(DigestDbEntrySet obj) {
        if (startId < obj.startId) {
            return -1;
        } else if (startId == obj.startId) {
            return 0;
        } else {
            return 1;
        }
    }

}
