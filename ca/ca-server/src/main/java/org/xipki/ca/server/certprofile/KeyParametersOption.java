/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.certprofile;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Lijun Liao
 */

public class KeyParametersOption
{
    public static final AllowAllParametersOption allowAll = new AllowAllParametersOption();

    public static class AllowAllParametersOption extends KeyParametersOption
    {
    }

    public static class RSAParametersOption extends KeyParametersOption
    {
        private Set<Range> modulusLengths;
        public RSAParametersOption()
        {
        }

        public void setModulusLengths(Set<Range> modulusLengths)
        {
            if(modulusLengths == null || modulusLengths.isEmpty())
            {
                this.modulusLengths = null;
            } else
            {
                this.modulusLengths = new HashSet<>(modulusLengths);
            }
        }

        public boolean allowsModulusLength(int modulusLength)
        {
            if(modulusLengths == null)
            {
                return true;
            }

            for(Range range : modulusLengths)
            {
                if(range.match(modulusLength))
                {
                    return true;
                }
            }
            return false;
        }
    }

    public static class RSAPSSParametersOption extends RSAParametersOption
    {
        private Set<ASN1ObjectIdentifier> hashAlgs;
        private Set<ASN1ObjectIdentifier> maskGenAlgs;
        private Set<Integer> saltLengths;
        private Set<Integer> trailerFields;

        public RSAPSSParametersOption()
        {
        }

        public void setHashAlgs(Set<ASN1ObjectIdentifier> hashAlgs)
        {
            if(hashAlgs == null || hashAlgs.isEmpty())
            {
                this.hashAlgs = null;
            } else
            {
                this.hashAlgs = new HashSet<>(hashAlgs);
            }
        }

        public void setMaskGenAlgs(Set<ASN1ObjectIdentifier> maskGenAlgs)
        {
            if(maskGenAlgs == null || maskGenAlgs.isEmpty())
            {
                this.maskGenAlgs = null;
            } else
            {
                this.maskGenAlgs = new HashSet<>(maskGenAlgs);
            }
        }

        public void setSaltLengths(Set<Integer> saltLengths)
        {
            if(saltLengths == null || saltLengths.isEmpty())
            {
                this.saltLengths = null;
            } else
            {
                this.saltLengths = new HashSet<>(saltLengths);
            }
        }

        public void setTrailerFields(Set<Integer> trailerFields)
        {
            if(trailerFields == null || trailerFields.isEmpty())
            {
                this.trailerFields = null;
            } else
            {
                this.trailerFields = new HashSet<>(trailerFields);
            }
        }

        public boolean allowsHashAlg(ASN1ObjectIdentifier hashAlg)
        {
            if(hashAlgs == null)
            {
                return true;
            }

            return hashAlgs.contains(hashAlg);
        }

        public boolean allowsMaskGenAlg(ASN1ObjectIdentifier maskGenAlg)
        {
            if(maskGenAlgs == null)
            {
                return true;
            }

            return maskGenAlgs.contains(maskGenAlg);
        }

        public boolean allowsSaltLength(int saltLength)
        {
            if(saltLengths == null)
            {
                return true;
            }

            return saltLengths.contains(saltLength);
        }

        public boolean allowsTrailerField(int trailerField)
        {
            if(trailerFields == null)
            {
                return true;
            }

            return trailerFields.contains(trailerField);
        }

    }

    public static class DSAParametersOption extends KeyParametersOption
    {
        private Set<Range> pLengths;
        private Set<Range> qLengths;

        public DSAParametersOption()
        {
        }

        public void setPLengths(Set<Range> pLengths)
        {
            if(pLengths == null || pLengths.isEmpty())
            {
                this.pLengths = null;
            } else
            {
                this.pLengths = new HashSet<>(pLengths);
            }
        }

        public void setQLengths(Set<Range> qLengths)
        {
            if(qLengths == null || qLengths.isEmpty())
            {
                this.qLengths = null;
            } else
            {
                this.qLengths = new HashSet<>(qLengths);
            }
        }

        public boolean allowsPLength(int pLength)
        {
            if(pLengths == null)
            {
                return true;
            }

            for(Range range : pLengths)
            {
                if(range.match(pLength))
                {
                    return true;
                }
            }

            return false;
        }

        public boolean allowsQLength(int qLength)
        {
            if(qLengths == null)
            {
                return true;
            }

            for(Range range : qLengths)
            {
                if(range.match(qLength))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public static class DHParametersOption extends DSAParametersOption
    {
    }

    public static class ECParamatersOption extends KeyParametersOption
    {
        private boolean implicitCAAllowed;
        private Set<ASN1ObjectIdentifier> curveOids;
        private Set<Byte> pointEncodings;

        public ECParamatersOption()
        {
        }

        public Set<ASN1ObjectIdentifier> getCurveOids()
        {
            return curveOids;
        }

        public void setCurveOids(Set<ASN1ObjectIdentifier> curveOids)
        {
            this.curveOids = curveOids;
        }

        public Set<Byte> getPointEncodings()
        {
            return pointEncodings;
        }

        public void setPointEncodings(Set<Byte> pointEncodings)
        {
            this.pointEncodings = pointEncodings;
        }

        public void setImplicitCAAllowed(boolean implicitCAAllowed)
        {
            this.implicitCAAllowed = implicitCAAllowed;
        }

        public boolean allowsImplicitCA()
        {
            return implicitCAAllowed;
        }

        public boolean allowsCurve(ASN1ObjectIdentifier curveOid)
        {
            return curveOids.add(curveOid);
        }

        public boolean allowsPointEncoding(byte encoding)
        {
            return pointEncodings.contains(encoding);
        }
    }

    public static class GostParametersOption extends KeyParametersOption
    {
        private Set<ASN1ObjectIdentifier> publicKeyParamSets;
        private Set<ASN1ObjectIdentifier> digestParamSets;
        private Set<ASN1ObjectIdentifier> encryptionParamSets;

        public GostParametersOption()
        {
        }

        public void setPublicKeyParamSets(Set<ASN1ObjectIdentifier> publicKeyParamSets)
        {
            if(publicKeyParamSets == null || publicKeyParamSets.isEmpty())
            {
                this.publicKeyParamSets = null;
            } else
            {
                this.publicKeyParamSets = new HashSet<>(publicKeyParamSets);
            }
        }

        public void setDigestParamSets(Set<ASN1ObjectIdentifier> digestParamSets)
        {
            if(digestParamSets == null || digestParamSets.isEmpty())
            {
                this.digestParamSets = null;
            } else
            {
                this.digestParamSets = new HashSet<>(digestParamSets);
            }
        }

        public void setEncryptionParamSets(Set<ASN1ObjectIdentifier> encryptionParamSets)
        {
            if(encryptionParamSets == null || encryptionParamSets.isEmpty())
            {
                this.encryptionParamSets = null;
            } else
            {
                this.encryptionParamSets = new HashSet<>(encryptionParamSets);
            }
        }

        public boolean allowsPublicKeyParamSet(ASN1ObjectIdentifier oid)
        {
            if(publicKeyParamSets == null)
            {
                return true;
            }
            return publicKeyParamSets.contains(oid);
        }

        public boolean allowsDigestParamSet(ASN1ObjectIdentifier oid)
        {
            if(digestParamSets == null)
            {
                return true;
            }
            return digestParamSets.contains(oid);
        }

        public boolean allowsEncryptionParamSet(ASN1ObjectIdentifier oid)
        {
            if(encryptionParamSets == null)
            {
                return true;
            }
            return encryptionParamSets.contains(oid);
        }
    }

}
