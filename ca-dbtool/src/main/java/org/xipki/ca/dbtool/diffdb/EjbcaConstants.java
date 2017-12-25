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

package org.xipki.ca.dbtool.diffdb;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaConstants {

    /**
     * Certificate doesn't belong to anyone.
     */
    public static final int CERT_UNASSIGNED = 0;

    /**
     * Assigned, but not yet active.
     */
    public static final int CERT_INACTIVE = 10;

    /**
     * Certificate is active and assigned.
     */
    public static final int CERT_ACTIVE = 20;

    /**
     * Certificate is temporarily blocked (reversible).
     */
    public static final int CERT_TEMP_REVOKED = 30;

    /**
     * Certificate is permanently blocked (terminated).
     */
    public static final int CERT_REVOKED = 40;

    /**
     * Certificate is expired.
     */
    public static final int CERT_EXPIRED = 50;

    /**
     * Certificate is expired and kept for archive purpose.
     */
    public static final int CERT_ARCHIVED = 60;

    private EjbcaConstants() {
    }

}
