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

package org.xipki.ca.client.api.dto;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EnrollCertRequest {

    public enum Type {

        CERT_REQ,
        KEY_UPDATE,
        CROSS_CERT_REQ;

    } // enum Type

    private final Type type;

    private final List<EnrollCertRequestEntry> requestEntries = new LinkedList<>();

    public EnrollCertRequest(final Type type) {
        this.type = ParamUtil.requireNonNull("type", type);
    }

    public Type type() {
        return type;
    }

    public boolean addRequestEntry(final EnrollCertRequestEntry requestEntry) {
        ParamUtil.requireNonNull("requestEntry", requestEntry);
        String id = requestEntry.id();
        ASN1Integer certReqId = requestEntry.certReq().getCertReqId();
        for (EnrollCertRequestEntry re : requestEntries) {
            if (re.id().equals(id)) {
                return false;
            }

            if (re.certReq().getCertReqId().equals(certReqId)) {
                return false;
            }
        }

        requestEntries.add(requestEntry);
        return true;
    }

    public List<EnrollCertRequestEntry> requestEntries() {
        return Collections.unmodifiableList(requestEntries);
    }

}
