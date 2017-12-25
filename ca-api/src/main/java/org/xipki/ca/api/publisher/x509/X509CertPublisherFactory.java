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

package org.xipki.ca.api.publisher.x509;

import org.xipki.common.ObjectCreationException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface X509CertPublisherFactory {

    /**
     *
     * @param type
     *          Type of the publisher. Must not be {@code null}.
     * @return whether publisher of this type can be created.
     */
    boolean canCreatePublisher(String type);

    /**
    *
    * @param type
    *          Type of the publisher. Must not be {@code null}.
    * @return the new created publisher
    * @throws ObjectCreationException
    *           if publisher could not be created.
    */
    X509CertPublisher newPublisher(String type) throws ObjectCreationException;

}
