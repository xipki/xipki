/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.security.provider;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * @author Lijun Liao
 */

class PlainECDSASignatureSpi extends AbstractECDSASignatureSpi {
    PlainECDSASignatureSpi(
            final Digest digest) {
        super(digest, false);
    }

    static public class SHA1
        extends PlainECDSASignatureSpi {
        public SHA1() {
            super(new SHA1Digest());
        }
    }

    static public class NONE
        extends PlainECDSASignatureSpi {
        public NONE() {
            super(new NullDigest());
        }
    }

    static public class SHA224
        extends PlainECDSASignatureSpi {
        public SHA224() {
            super(new SHA224Digest());
        }
    }

    static public class SHA256
        extends PlainECDSASignatureSpi {
        public SHA256() {
            super(new SHA256Digest());
        }
    }

    static public class SHA384
        extends PlainECDSASignatureSpi {
        public SHA384() {
            super(new SHA384Digest());
        }
    }

    static public class SHA512
        extends PlainECDSASignatureSpi {
        public SHA512() {
            super(new SHA512Digest());
        }
    }

    static public class RIPEMD160
        extends PlainECDSASignatureSpi {
        public RIPEMD160() {
            super(new RIPEMD160Digest());
        }
    }

}
