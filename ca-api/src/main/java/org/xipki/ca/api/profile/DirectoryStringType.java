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

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum DirectoryStringType {

    teletexString,
    printableString,
    utf8String,
    bmpString;

    public ASN1Encodable createDirectoryString(final String text) {
        ParamUtil.requireNonNull("text", text);

        if (teletexString == this) {
            return new DERT61String(text);
        } else if (printableString == this) {
            return new DERPrintableString(text);
        } else if (utf8String == this) {
            return new DERUTF8String(text);
        } else if (bmpString == this) {
            return new DERBMPString(text);
        } else {
            throw new RuntimeException(
                    "should not reach here, unknown DirectoryStringType " + this.name());
        }
    }

}
