/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.api.profile;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyParametersOption {

    public static class AllowAllParametersOption extends KeyParametersOption {
    } // class AllowAllParametersOption

    // CHECKSTYLE:SKIP
    public static class RSAParametersOption extends KeyParametersOption {

        private Set<Range> modulusLengths;

        public RSAParametersOption() {
        }

        public void setModulusLengths(final Set<Range> modulusLengths) {
            this.modulusLengths = (CollectionUtil.isEmpty(modulusLengths)) ? null
                    : new HashSet<>(modulusLengths);
        }

        public boolean allowsModulusLength(final int modulusLength) {
            if (modulusLengths == null) {
                return true;
            }

            for (Range range : modulusLengths) {
                if (range.match(modulusLength)) {
                    return true;
                }
            }
            return false;
        }

    } // class RSAParametersOption

    // CHECKSTYLE:SKIP
    public static class RSAPSSParametersOption extends RSAParametersOption {

        private Set<ASN1ObjectIdentifier> hashAlgs;

        private Set<ASN1ObjectIdentifier> maskGenAlgs;

        private Set<Integer> saltLengths;

        private Set<Integer> trailerFields;

        public RSAPSSParametersOption() {
        }

        public void setHashAlgs(final Set<ASN1ObjectIdentifier> hashAlgs) {
            this.hashAlgs = CollectionUtil.isEmpty(hashAlgs) ? null : new HashSet<>(hashAlgs);
        }

        public void setMaskGenAlgs(final Set<ASN1ObjectIdentifier> maskGenAlgs) {
            this.maskGenAlgs = CollectionUtil.isEmpty(maskGenAlgs) ? null
                    : new HashSet<>(maskGenAlgs);
        }

        public void setSaltLengths(final Set<Integer> saltLengths) {
            this.saltLengths = CollectionUtil.isEmpty(saltLengths) ? null
                    : new HashSet<>(saltLengths);
        }

        public void setTrailerFields(final Set<Integer> trailerFields) {
            this.trailerFields = CollectionUtil.isEmpty(trailerFields) ? null
                    : new HashSet<>(trailerFields);
        }

        public boolean allowsHashAlg(final ASN1ObjectIdentifier hashAlg) {
            return (hashAlgs == null) ? true : hashAlgs.contains(hashAlg);
        }

        public boolean allowsMaskGenAlg(final ASN1ObjectIdentifier maskGenAlg) {
            return (maskGenAlgs == null) ? true : maskGenAlgs.contains(maskGenAlg);
        }

        public boolean allowsSaltLength(final int saltLength) {
            return (saltLengths == null) ? true : saltLengths.contains(saltLength);
        }

        public boolean allowsTrailerField(final int trailerField) {
            return (trailerFields == null) ? true : trailerFields.contains(trailerField);
        }

    } // class RSAPSSParametersOption

    // CHECKSTYLE:SKIP
    public static class DSAParametersOption extends KeyParametersOption {

        private Set<Range> plengths;

        private Set<Range> qlengths;

        public DSAParametersOption() {
        }

        public void setPlengths(final Set<Range> plengths) {
            this.plengths = CollectionUtil.isEmpty(plengths) ? null : new HashSet<>(plengths);
        }

        public void setQlengths(final Set<Range> qlengths) {
            this.qlengths = CollectionUtil.isEmpty(qlengths) ? null : new HashSet<>(qlengths);
        }

        public boolean allowsPlength(final int plength) {
            if (plengths == null) {
                return true;
            }

            for (Range range : plengths) {
                if (range.match(plength)) {
                    return true;
                }
            }

            return false;
        }

        public boolean allowsQlength(final int qlength) {
            if (qlengths == null) {
                return true;
            }

            for (Range range : qlengths) {
                if (range.match(qlength)) {
                    return true;
                }
            }

            return false;
        }

    } // class DSAParametersOption

    // CHECKSTYLE:SKIP
    public static class DHParametersOption extends DSAParametersOption {
    } // class DHParametersOption

    // CHECKSTYLE:SKIP
    public static class ECParamatersOption extends KeyParametersOption {

        private Set<ASN1ObjectIdentifier> curveOids;

        private Set<Byte> pointEncodings;

        public ECParamatersOption() {
        }

        public Set<ASN1ObjectIdentifier> curveOids() {
            return curveOids;
        }

        public void setCurveOids(final Set<ASN1ObjectIdentifier> curveOids) {
            this.curveOids = curveOids;
        }

        public Set<Byte> pointEncodings() {
            return pointEncodings;
        }

        public void setPointEncodings(final Set<Byte> pointEncodings) {
            this.pointEncodings = pointEncodings;
        }

        public boolean allowsCurve(final ASN1ObjectIdentifier curveOid) {
            ParamUtil.requireNonNull("curveOid", curveOid);
            return (curveOids == null) ? true : curveOids.contains(curveOid);
        }

        public boolean allowsPointEncoding(final byte encoding) {
            return (pointEncodings == null) ? true : pointEncodings.contains(encoding);
        }

    } // class ECParamatersOption

    public static class GostParametersOption extends KeyParametersOption {

        private Set<ASN1ObjectIdentifier> publicKeyParamSets;

        private Set<ASN1ObjectIdentifier> digestParamSets;

        private Set<ASN1ObjectIdentifier> encryptionParamSets;

        public GostParametersOption() {
        }

        public void setPublicKeyParamSets(final Set<ASN1ObjectIdentifier> publicKeyParamSets) {
            if (CollectionUtil.isEmpty(publicKeyParamSets)) {
                this.publicKeyParamSets = null;
            } else {
                this.publicKeyParamSets = new HashSet<>(publicKeyParamSets);
            }
        }

        public void setDigestParamSets(final Set<ASN1ObjectIdentifier> digestParamSets) {
            this.digestParamSets = CollectionUtil.isEmpty(digestParamSets) ? null
                    : new HashSet<>(digestParamSets);
        }

        public void setEncryptionParamSets(final Set<ASN1ObjectIdentifier> encryptionParamSets) {
            this.encryptionParamSets =  CollectionUtil.isEmpty(encryptionParamSets) ? null
                    : new HashSet<>(encryptionParamSets);
        }

        public boolean allowsPublicKeyParamSet(final ASN1ObjectIdentifier oid) {
            if (publicKeyParamSets == null) {
                return true;
            }
            ParamUtil.requireNonNull("oid", oid);
            return publicKeyParamSets.contains(oid);
        }

        public boolean allowsDigestParamSet(final ASN1ObjectIdentifier oid) {
            if (digestParamSets == null) {
                return true;
            }
            ParamUtil.requireNonNull("oid", oid);
            return digestParamSets.contains(oid);
        }

        public boolean allowsEncryptionParamSet(final ASN1ObjectIdentifier oid) {
            if (encryptionParamSets == null) {
                return true;
            }
            ParamUtil.requireNonNull("oid", oid);
            return encryptionParamSets.contains(oid);
        }

    } // class GostParametersOption

    public static final AllowAllParametersOption ALLOW_ALL = new AllowAllParametersOption();

    private KeyParametersOption() {
    }

}
