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

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestResponsePair {

    private byte[] request;

    private byte[] response;

    public byte[] request() {
        return request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public byte[] response() {
        return response;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

}
