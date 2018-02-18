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

import java.util.Set;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 3.0.1
 */

public class UnmodifiableConfPairs extends ConfPairs {

    private final ConfPairs underlying;

    public UnmodifiableConfPairs(String encodedConfPairs) {
        this.underlying = new ConfPairs(encodedConfPairs);
    }

    public UnmodifiableConfPairs(ConfPairs underlying) {
        this.underlying = ParamUtil.requireNonNull("underlying", underlying);
    }

    @Override
    public void putPair(String name, String value) {
        throw new UnsupportedOperationException("putPair() is not supported");
    }

    @Override
    public void removePair(String name) {
        throw new UnsupportedOperationException("removePair() is not supported");
    }

    @Override
    public String value(String name) {
        return underlying.value(name);
    }

    @Override
    public Set<String> names() {
        return underlying.names();
    }

    @Override
    public String getEncoded() {
        return underlying.getEncoded();
    }

    @Override
    public String toString() {
        return underlying.toString();
    }

    @Override
    public int hashCode() {
        return underlying.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof UnmodifiableConfPairs) {
            UnmodifiableConfPairs other = (UnmodifiableConfPairs) obj;
            return this.underlying.equals(other.underlying);
        }

        return underlying.equals(obj);
    }

}
