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

package org.xipki.common.qa;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ValidationIssue {

    private final String code;

    private final String description;

    private boolean failed;

    private String failureMessage;

    public ValidationIssue(final String code, final String description) {
        this.code = ParamUtil.requireNonBlank("code", code);
        this.description = ParamUtil.requireNonBlank("description", description);
        this.failed = false;
    }

    public boolean isFailed() {
        return failed;
    }

    public String failureMessage() {
        return failureMessage;
    }

    public void setFailureMessage(final String failureMessage) {
        this.failureMessage = ParamUtil.requireNonNull("failureMessage", failureMessage);
        this.failed = true;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }

}
