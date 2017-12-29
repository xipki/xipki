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

        public void setModulusLengths(Set<Range> modulusLengths) {
            this.modulusLengths = (CollectionUtil.isEmpty(modulusLengths)) ? null
                    : new HashSet<>(modulusLengths);
        }

        public boolean allowsModulusLength(int modulusLength) {
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

        public void setHashAlgs(Set<ASN1ObjectIdentifier> hashAlgs) {
            this.hashAlgs = CollectionUtil.isEmpty(hashAlgs) ? null : new HashSet<>(hashAlgs);
        }

        public void setMaskGenAlgs(Set<ASN1ObjectIdentifier> maskGenAlgs) {
            this.maskGenAlgs = CollectionUtil.isEmpty(maskGenAlgs) ? null
                    : new HashSet<>(maskGenAlgs);
        }

        public void setSaltLengths(Set<Integer> saltLengths) {
            this.saltLengths = CollectionUtil.isEmpty(saltLengths) ? null
                    : new HashSet<>(saltLengths);
        }

        public void setTrailerFields(Set<Integer> trailerFields) {
            this.trailerFields = CollectionUtil.isEmpty(trailerFields) ? null
                    : new HashSet<>(trailerFields);
        }

        public boolean allowsHashAlg(ASN1ObjectIdentifier hashAlg) {
            return (hashAlgs == null) ? true : hashAlgs.contains(hashAlg);
        }

        public boolean allowsMaskGenAlg(ASN1ObjectIdentifier maskGenAlg) {
            return (maskGenAlgs == null) ? true : maskGenAlgs.contains(maskGenAlg);
        }

        public boolean allowsSaltLength(int saltLength) {
            return (saltLengths == null) ? true : saltLengths.contains(saltLength);
        }

        public boolean allowsTrailerField(int trailerField) {
            return (trailerFields == null) ? true : trailerFields.contains(trailerField);
        }

    } // class RSAPSSParametersOption

    // CHECKSTYLE:SKIP
    public static class DSAParametersOption extends KeyParametersOption {

        private Set<Range> plengths;

        private Set<Range> qlengths;

        public DSAParametersOption() {
        }

        public void setPlengths(Set<Range> plengths) {
            this.plengths = CollectionUtil.isEmpty(plengths) ? null : new HashSet<>(plengths);
        }

        public void setQlengths(Set<Range> qlengths) {
            this.qlengths = CollectionUtil.isEmpty(qlengths) ? null : new HashSet<>(qlengths);
        }

        public boolean allowsPlength(int plength) {
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

        public boolean allowsQlength(int qlength) {
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

        public void setCurveOids(Set<ASN1ObjectIdentifier> curveOids) {
            this.curveOids = curveOids;
        }

        public Set<Byte> pointEncodings() {
            return pointEncodings;
        }

        public void setPointEncodings(Set<Byte> pointEncodings) {
            this.pointEncodings = pointEncodings;
        }

        public boolean allowsCurve(ASN1ObjectIdentifier curveOid) {
            ParamUtil.requireNonNull("curveOid", curveOid);
            return (curveOids == null) ? true : curveOids.contains(curveOid);
        }

        public boolean allowsPointEncoding(byte encoding) {
            return (pointEncodings == null) ? true : pointEncodings.contains(encoding);
        }

    } // class ECParamatersOption

    public static class GostParametersOption extends KeyParametersOption {

        private Set<ASN1ObjectIdentifier> publicKeyParamSets;

        private Set<ASN1ObjectIdentifier> digestParamSets;

        private Set<ASN1ObjectIdentifier> encryptionParamSets;

        public GostParametersOption() {
        }

        public void setPublicKeyParamSets(Set<ASN1ObjectIdentifier> publicKeyParamSets) {
            if (CollectionUtil.isEmpty(publicKeyParamSets)) {
                this.publicKeyParamSets = null;
            } else {
                this.publicKeyParamSets = new HashSet<>(publicKeyParamSets);
            }
        }

        public void setDigestParamSets(Set<ASN1ObjectIdentifier> digestParamSets) {
            this.digestParamSets = CollectionUtil.isEmpty(digestParamSets) ? null
                    : new HashSet<>(digestParamSets);
        }

        public void setEncryptionParamSets(Set<ASN1ObjectIdentifier> encryptionParamSets) {
            this.encryptionParamSets =  CollectionUtil.isEmpty(encryptionParamSets) ? null
                    : new HashSet<>(encryptionParamSets);
        }

        public boolean allowsPublicKeyParamSet(ASN1ObjectIdentifier oid) {
            if (publicKeyParamSets == null) {
                return true;
            }
            ParamUtil.requireNonNull("oid", oid);
            return publicKeyParamSets.contains(oid);
        }

        public boolean allowsDigestParamSet(ASN1ObjectIdentifier oid) {
            if (digestParamSets == null) {
                return true;
            }
            ParamUtil.requireNonNull("oid", oid);
            return digestParamSets.contains(oid);
        }

        public boolean allowsEncryptionParamSet(ASN1ObjectIdentifier oid) {
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
