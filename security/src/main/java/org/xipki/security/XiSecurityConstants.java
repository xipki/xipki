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

package org.xipki.security;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XiSecurityConstants {

    public static final String PROVIDER_NAME_XIPKI = "XIPKI";

    public static final int CMP_CRL_REASON_REMOVE = -1;

    public static final int CMP_ACTION_GEN_CRL = 1;

    public static final int CMP_ACTION_GET_CRL_WITH_SN = 2;

    public static final int CMP_ACTION_GET_CAINFO = 3;

    private XiSecurityConstants() {
    }

}
