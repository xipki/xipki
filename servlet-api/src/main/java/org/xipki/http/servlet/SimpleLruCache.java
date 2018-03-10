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

package org.xipki.http.servlet;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

class SimpleLruCache<K, V> {

  private final LinkedHashMap<K, V> map;

  /** Size of this cache in units. Not necessarily the number of elements. */
  private int size;

  private int maxSize;

  private int putCount;

  private int evictionCount;

  private int hitCount;

  private int missCount;

  /**
   * TODO.
   * @param maxSize for caches that do not override {@link #sizeOf}, this is
   *     the maximum number of entries in the cache. For all other caches,
   *     this is the maximum sum of the sizes of the entries in this cache.
   */
  SimpleLruCache(int maxSize) {
    if (maxSize < 1) {
      throw new IllegalArgumentException("maxSize must not be less than 1");
    }
    this.map = new LinkedHashMap<>(0, 0.75f, true);
  }

  /**
   * Returns the value for {@code key} if it exists in the cache or can be
   * created by {@code #create}. If a value was returned, it is moved to the
   * head of the queue. This returns null if a value is not cached and could not
   * be created.
   */
  final V get(K key) {
    if (key == null) {
      throw new NullPointerException("key == null");
    }

    V mapValue;
    synchronized (this) {
      mapValue = map.get(key);
      if (mapValue != null) {
        hitCount++;
        return mapValue;
      }
      missCount++;
    }

    return null;
  }

  /**
   * Caches {@code value} for {@code key}. The value is moved to the head of
   * the queue.
   *
   * @return the previous value mapped by {@code key}.
   */
  final V put(K key, V value) {
    if (key == null || value == null) {
      throw new NullPointerException("key == null || value == null");
    }

    V previous;
    synchronized (this) {
      putCount++;
      size += 1;
      previous = map.put(key, value);
      if (previous != null) {
        size -= 1;
      }
    }

    trimToSize(maxSize);
    return previous;
  }

  /**
   * Remove the eldest entries until the total of remaining entries is at or
   * below the requested size.
   *
   * @param pMaxSize the maximum size of the cache before returning. Could be -1
   *            to evict even 0-sized elements.
   */
  private void trimToSize(int maxSize) {
    while (true) {
      K key;
      synchronized (this) {
        if (size < 0 || (map.isEmpty() && size != 0)) {
          throw new IllegalStateException(getClass().getName()
              + ".sizeOf() is reporting inconsistent results!");
        }

        if (size <= maxSize || map.isEmpty()) {
          break;
        }

        Map.Entry<K, V> toEvict = map.entrySet().iterator().next();
        key = toEvict.getKey();
        map.remove(key);
        size -= 1;
        evictionCount++;
      }
    }
  }

  @Override
  public final synchronized String toString() {
    int accesses = hitCount + missCount;
    int hitPercent = (accesses == 0) ? 0 : (100 * hitCount / accesses);
    return String.format("LruCache[maxSize=%d,hits=%d,misses=%d,hitRate=%d%%]",
        maxSize, hitCount, missCount, hitPercent);
  }

}
