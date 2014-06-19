/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.cmp.client;

/**
 * @author Lijun Liao
 */

public class ClientErrorCode
{
    /**
     * Intern status to indicate that there are errors in the response
     */
    public static final int PKIStatus_RESPONSE_ERROR = -1;

    public static final int PKIStatus_NO_ANSWER = -2;
}
