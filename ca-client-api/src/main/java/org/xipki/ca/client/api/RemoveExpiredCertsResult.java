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

package org.xipki.ca.client.api;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RemoveExpiredCertsResult {

    private int numOfCerts;

    private long expiredAt;

    private String userLike;

    private String certprofile;

    public int numOfCerts() {
        return numOfCerts;
    }

    public void setNumOfCerts(final int numOfCerts) {
        this.numOfCerts = numOfCerts;
    }

    public long expiredAt() {
        return expiredAt;
    }

    public void setExpiredAt(final long expiredAt) {
        this.expiredAt = expiredAt;
    }

    public String userLike() {
        return userLike;
    }

    public void setUserLike(final String userLike) {
        this.userLike = userLike;
    }

    public String certprofile() {
        return certprofile;
    }

    public void setCertprofile(final String certprofile) {
        this.certprofile = certprofile;
    }

}
