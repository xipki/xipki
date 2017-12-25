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

package org.xipki.ocsp.server.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.xipki.common.InvalidConfException;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.api.OcspMode;
import org.xipki.ocsp.server.impl.jaxb.ResponderType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class ResponderOption {

    private final OcspMode mode;

    private final boolean inheritCaRevocation;

    private final String requestOptionName;

    private final String responseOptionName;

    private final String signerName;

    private final List<String> storeNames;

    private final List<String> servletPaths;

    ResponderOption(final ResponderType conf) throws InvalidConfException {
        ParamUtil.requireNonNull("conf", conf);
        String str = conf.getMode();
        if (str == null || "RFC6960".equalsIgnoreCase(str) || "RFC 6960".equalsIgnoreCase(str)) {
            this.mode = OcspMode.RFC6960;
        } else if ("RFC2560".equalsIgnoreCase(str) || "RFC 2560".equals(str)) {
            this.mode = OcspMode.RFC2560;
        } else {
            throw new InvalidConfException("invalid OCSP mode '" + str + "'");
        }

        this.signerName = conf.getSigner();
        this.requestOptionName = conf.getRequest();
        this.responseOptionName = conf.getResponse();
        this.inheritCaRevocation = conf.isInheritCaRevocation();

        List<String> list = new ArrayList<>(conf.getStores().getStore());
        this.storeNames = Collections.unmodifiableList(list);

        List<String> paths = conf.getServletPaths().getServletPath();
        for (String path : paths) {
            if (path.isEmpty()) {
                continue;
            }

            if (path.charAt(0) != '/') {
                throw new InvalidConfException(
                        "servlet path '" + path + "' must start with '/'");
            }
        }
        list = new ArrayList<>(paths);
        this.servletPaths = Collections.unmodifiableList(list);
    } // constructor

    public OcspMode mode() {
        return mode;
    }

    public boolean inheritCaRevocation() {
        return inheritCaRevocation;
    }

    public String signerName() {
        return signerName;
    }

    public String requestOptionName() {
        return requestOptionName;
    }

    public String responseOptionName() {
        return responseOptionName;
    }

    public List<String> storeNames() {
        return storeNames;
    }

    public List<String> servletPaths() {
        return servletPaths;
    }

}
