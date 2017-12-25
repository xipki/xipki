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

package org.xipki.ca.server.mgmt.api.x509;

import java.util.List;

import org.xipki.common.util.CollectionUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaUris {
    private final List<String> cacertUris;
    private final List<String> ocspUris;
    private final List<String> crlUris;
    private final List<String> deltaCrlUris;

    public X509CaUris(final List<String> cacertUris, final List<String> ocspUris,
            final List<String> crlUris, final List<String> deltaCrlUris) {
        this.cacertUris = cacertUris;
        this.ocspUris = ocspUris;
        this.crlUris = crlUris;
        this.deltaCrlUris = deltaCrlUris;
    }

    public List<String> cacertUris() {
        return CollectionUtil.unmodifiableList(cacertUris);
    }

    public List<String> ocspUris() {
        return CollectionUtil.unmodifiableList(ocspUris);
    }

    public List<String> crlUris() {
        return CollectionUtil.unmodifiableList(crlUris);
    }

    public List<String> deltaCrlUris() {
        return CollectionUtil.unmodifiableList(deltaCrlUris);
    }

}
