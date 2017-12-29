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

package org.xipki.ocsp.client.shell;

import java.util.HashMap;
import java.util.Map;

import org.xipki.ocsp.client.api.OcspResponseException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@SuppressWarnings("serial")
public class OcspResponseUnsuccessfulException extends OcspResponseException {

    private static final Map<Integer, String> codeStatusMap = new HashMap<>();

    private int status;

    static {
        codeStatusMap.put(1, "malformedRequest");
        codeStatusMap.put(2, "internalError");
        codeStatusMap.put(3, "tryLater");
        codeStatusMap.put(5, "sigRequired");
        codeStatusMap.put(6, "unauthorized");
    }

    public OcspResponseUnsuccessfulException(int status) {
        super(getOcspResponseStatus(status));
        this.status = status;
    }

    public int status() {
        return status;
    }

    public String statusText() {
        return getOcspResponseStatus(status);
    }

    private static String getOcspResponseStatus(int statusCode) {
        String status = codeStatusMap.get(statusCode);
        return (status == null) ? "undefined" : status;
    }

}
