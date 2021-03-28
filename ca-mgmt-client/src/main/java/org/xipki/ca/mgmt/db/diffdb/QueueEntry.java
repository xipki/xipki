/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.mgmt.db.diffdb;

import java.util.LinkedList;
import java.util.List;

/**
 * Entry of a queue.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

interface QueueEntry {

  EndOfQueue END_OF_QUEUE = new EndOfQueue();

  class EndOfQueue implements QueueEntry {

    private EndOfQueue() {
    }

  } // class EndOfQueue

  class DigestEntrySet implements QueueEntry, Comparable<DigestEntrySet> {

    private final long startId;

    private Exception exception;

    private final List<IdentifiedDigestEntry> entries = new LinkedList<>();

    public DigestEntrySet(long startId) {
      this.startId = startId;
    }

    public void setException(Exception exception) {
      this.exception = exception;
    }

    public Exception getException() {
      return exception;
    }

    public void addEntry(IdentifiedDigestEntry entry) {
      entries.add(entry);
    }

    public long getStartId() {
      return startId;
    }

    public List<IdentifiedDigestEntry> getEntries() {
      return entries;
    }

    @Override
    public int compareTo(DigestEntrySet obj) {
      return Long.compare(startId, obj.startId);
    }

  } // class DigestEntrySet
}
