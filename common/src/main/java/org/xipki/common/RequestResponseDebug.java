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

package org.xipki.common;

import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestResponseDebug {

    private final List<RequestResponsePair> pairs = new LinkedList<>();

    public void add(final RequestResponsePair pair) {
        pairs.add(pair);
    }

    public int size() {
        return pairs.size();
    }

    public RequestResponsePair get(final int index) {
        return pairs.get(index);
    }

    public boolean remove(final RequestResponsePair pair) {
        return pairs.remove(pair);
    }

    public RequestResponsePair remove(final int index) {
        return pairs.remove(index);
    }

}
