/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.server.impl.scep;

import org.xipki.common.util.ParamUtil;
import org.xipki.scep.transaction.FailInfo;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class FailInfoException extends Exception {

    public static final FailInfoException BAD_ALG = new FailInfoException(FailInfo.badAlg);

    public static final FailInfoException BAD_CERTID = new FailInfoException(FailInfo.badCertId);

    public static final FailInfoException BAD_MESSAGE_CHECK
            = new FailInfoException(FailInfo.badMessageCheck);

    public static final FailInfoException BAD_REQUEST = new FailInfoException(FailInfo.badRequest);

    public static final FailInfoException BAD_TIME = new FailInfoException(FailInfo.badTime);

    private static final long serialVersionUID = 1L;

    private final FailInfo failInfo;

    private FailInfoException(final FailInfo failInfo) {
        this.failInfo = ParamUtil.requireNonNull("failInfo", failInfo);
    }

    public FailInfo failInfo() {
        return failInfo;
    }

}
