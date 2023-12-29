// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import java.util.LinkedList;
import java.util.List;

/**
 * Entry of a queue.
 *
 * @author Lijun Liao (xipki)
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

    void addEntry(IdentifiedDigestEntry entry) {
      entries.add(entry);
    }

    long getStartId() {
      return startId;
    }

    List<IdentifiedDigestEntry> getEntries() {
      return entries;
    }

    @Override
    public int compareTo(DigestEntrySet obj) {
      return Long.compare(startId, obj.startId);
    }

  } // class DigestEntrySet
}
