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

package org.xipki.security.exception;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class BadAsn1ObjectException extends Exception {

    private static final long serialVersionUID = 1L;

    public BadAsn1ObjectException() {
    }

    public BadAsn1ObjectException(String message) {
        super(message);
    }

    public BadAsn1ObjectException(Throwable cause) {
        super(cause);
    }

    public BadAsn1ObjectException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadAsn1ObjectException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
