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

package org.xipki.ca.qa.internal;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class QaPolicyQualifierInfo {

    public static class QaCpsUriPolicyQualifier extends QaPolicyQualifierInfo {

        private final String cpsUri;

        public QaCpsUriPolicyQualifier(String cpsUri) {
            this.cpsUri = ParamUtil.requireNonBlank("cpsUri", cpsUri);
        }

        public String cpsUri() {
            return cpsUri;
        }

    } // class QaCPSUriPolicyQualifier

    public static class QaUserNoticePolicyQualifierInfo extends QaPolicyQualifierInfo {

        private final String userNotice;

        public QaUserNoticePolicyQualifierInfo(String userNotice) {
            this.userNotice = ParamUtil.requireNonBlank("userNotice", userNotice);
        }

        public String userNotice() {
            return userNotice;
        }

    } // class QaUserNoticePolicyQualifierInfo

}
