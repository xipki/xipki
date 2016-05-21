/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;

/**
 * Cache for DSA parameter specs.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
final class DSAParameterCache {
    private static final Map<String, DSAParameterSpec> cache = new HashMap<>();

    static {
        // plen: 1024, qlen: 160
        String strP =
                "CC7602EFB290B0DFC3548EA0560CB9AF4485A55B1A6D2EE21CFF9F8C26EF0A9C"
                + "9D989BD14B144B372F38583C5F29C79C9BCE73E21E4A30DD21DF211252C16B87"
                + "FFB39CC0380358543C601F615464BFD8A72023F3F1B1AE44057E609EBB5AA6A0"
                + "9BA6BD06873833F8872D3478AF83B6BAFB77979ADDF66D4B3737A063CA69438B";

        String strQ =
                "9180AC2B78B185AEB5C71BA1B4EB116193453B61";

        String strG =
                "1E3A7166465E5441104CE79B435157199292441D69BE085D15829640D5D4F6B2"
                + "43B5C7515D887D775994817A10548BFA773303E41128D9E3398BB95E2ADB8296"
                + "4C49669DCCEFC9A3C9FA4BD55541F416F2262BF4B4A5EC41A46BEE887BDF96A9"
                + "718AED50A94C5758C29E5E2C7BBE3D108C65EA5A7D9FF6F8EDC1183D965F86D9";

        addDSAParamSpec(1024, 160, strP, strQ, strG);

        // plen: 2048, qlen: 224
        strP =
                "EDA919C7B9A1891ED5F1649E552D804AC9821F32C7F9E73086437516CE89831D"
                + "52BAD8F73D60388C3F87641F66A9DABDDAA0D78F73A0627A98947C2472F1F0DD"
                + "9D1BF5249C1C334B9DA30D5DE1C8957131D00E4DC82A0D00E4C54DA3DD9A611D"
                + "63D5D94BCE34FCDDD749329E46C31A4C62FF1BD5B85948BEB42D864B817509CC"
                + "471ADBB6BD3FEF1F26CED8A919A0992ACD5E3A870A1575D4AF173E8C09E6DF1C"
                + "6F1FF19B28FECF2B08D6E59595F92A8B3B77F82F2BD03D2ABB11049007CDA2CD"
                + "B55B6C29C550D8EBE34852A828D05EEEF3E04777FE38307E874B800BF3DF92DE"
                + "F1012615E9834075F447294EBBEE5DFA16A51AA61368C49B85FD7F37138184CD";
        strQ =
                "D1A1DDDE587A95BE124F57D5A974A282E3E432632E3A0B55AE5AEE19";
        strG =
                "421A0F322C89EB745339B6165AE0C9FC1138317EC3AAF9A630E1C147CA043365"
                + "6D3C4890DCD64A2B77ED7A59FF0055F03AEDB14AD54E456BC89CAB317B405E2E"
                + "E0E1384FBC5F43A83C6B5DB1131181A57034BD4020E17A5D3DFF52A0C7C47A19"
                + "746483AC56F7CD9ADEBD3E4DD28FDD9F1763F9B8875E175AC4C3429B25F08E74"
                + "1ABBBA7007F9D187900B9EF3E38C5429F906F8C927A828A31168CDA4B388EED4"
                + "E963D41FE01DF6E67826A48D6711B5A302205EE3905B5C9E8DB3CC0E063007D2"
                + "847C7B20FE2A602D5D63AA8FEAC6E09E23C017BE150724FCECE1369421610635"
                + "CA5C04DE00677A6176058C83FC0D7B951CD722E5ED77562AF2209A25DC8B5108";
        addDSAParamSpec(2048, 224, strP, strQ, strG);

        // plen: 2048, qlen: 256
        strP =
                "E13AC60336C29FAF1B48393D80C74B781E15E23E3F59F0827190FF016720A8E0"
                + "DAC2D4FF699EBA2196E1B9815ECAE0506441A4BC4DA97E97F2723A808EF6B634"
                + "3968906137B04B23F6540FC4B9D7C0A46635B6D52AEDD08347370B9BE43A7222"
                + "807655CB5ED480F4C66128357D0E0A2C62785DC38160645661FA569ADCE46D3B"
                + "3BFAB114613436242855F5717143D51FB365972F6B8695C2186CBAD1E8C5B4D3"
                + "1AD70876EBDD1C2191C5FB6C4804E0D38CBAA054FC7AFD25E0F2735F726D8A31"
                + "DE97431BFB6CF1AD563811830131E7D5E5117D92389406EF436A8077E69B8795"
                + "18436E33A9F221AB3A331680D0345B316F5BEBDA8FBF70612BEC734272E760BF";

        strQ =
                "9CF2A23A8F95FEFB0CA67212991AC172FDD3F4D70401B684C3E4223D46D090E5";

        strG =
                "1CBEF6EEB9E73C5997BF64CA8BCC33CDC6AFC5601B86FDE1B0AC4C34066DFBF9"
                + "9B80CCE264C909B32CF88CE09CB73476C0A6E701092E09C93507FE3EBD425B75"
                + "8AE3C5E3FDC1076AF237C5EF40A790CF6555EB3408BCEF212AC5A1C125A7183D"
                + "24935554C0D258BF1F6A5A6D05C0879DB92D32A0BCA3A85D42F9B436AE97E62E"
                + "0E30E53B8690D8585493D291969791EA0F3B062645440587C031CD2880481E0B"
                + "E3253A28EFFF3ACEB338A2FE4DB8F652E0FDA277268B73D5E532CF9E4E2A1CAB"
                + "738920F760012DD9389F35E0AA7C8528CE173934529397DABDFAA1E77AF83FAD"
                + "629AC102596885A06B5C670FFA838D37EB55FE7179A88F6FF927B37E0F827726";
        addDSAParamSpec(2048, 256, strP, strQ, strG);

        // plen: 3072, qlen: 256
        strP =
                "E1CD75FD92FF448A6AEFDF36FA26BC3D933E258B4887BD7217006CE79844E569"
                + "E82A44A496D3102F8AFC75CF9012A759DDBBEFB59579D78F1C3ECECDDE0130D1"
                + "5C965C5B291FFE5ED33924A6D601C69FE2C6FEC8F5C34D9D4C3164F9F975CFCE"
                + "1EDD0D957B9448DC66B4248E646901BFF9EF2C5031A0E8D38B3644D69619795B"
                + "D059A3E9EECAA6FA33449F3579BCEEC6F703F179A77503928A4864419A4DA8D2"
                + "99954EF5C38A08CF237522D125821D76A744FD75B1D14043F17AEADEE638F3D8"
                + "6A2F5CC0C214E14C0D4B041B27B6C5CC3FF1EF6C0DAB9FA76EAD3D35F7443142"
                + "967B3FD37F22635B793BAA41014022477CFC83E9947EF7C8BA6C2F7443C401BA"
                + "E5604BF7516F23925C45ABBFCF772096808FF471D63CF877F620DC9EAFA24077"
                + "C27DFCC5E4EF638D92943007A07CFFF9498227766927462F3D4FCCBF94816236"
                + "6D34B643556776218E333FBD45742DD866D3CC6EF12661D50AD28A7B2465B2CB"
                + "F2714251C0D8383544286E606CB2463DD15CFFD94E546CCBC40552035E32ECEB";

        strQ =
                "9E716023B076F10F716F4006F8470C90B0273B67BBA2E96ADE8BF51A70990B39";

        strG =
                "735B04ACFA7A2B30207ABAA0770728A6D9F530674BAE28E0EA373972D2F451FD"
                + "0E64F4AB0EA381590CF48049C20A4658A32FA1824098AF7AEE202A3F26862A82"
                + "DAF93B70D26650C4831FCF27E7CD43E9EF9166AAB100291CC59088EC61524D79"
                + "37209713385024EA5CE3832D48EA76F965BE55EA54C944CE24485918FFE17672"
                + "E35187EA03F7B0E1B5423A1E6EF1313AA24CCBDDFDAD45747E9A0459A5B80930"
                + "AC413DFA9E88B0812EAC0C6BEFA86254F7951ADC7B921CF65E8746E1CD849D09"
                + "1422A13D90EC5F7C05B1402DD20557177C9CFCE85586B10E162748DBD12B28EA"
                + "CE56A6AAC8AF69BA9EB721E1871B2993FD627C4FE73B38BD346A988F5245084E"
                + "D13999B3B5AB2F3C93A8CE119222321F97F0D0453A08F42D564BF68F49C56D6A"
                + "41795EC4D2E332B2D78226AC048C9C669280D1CD6492E38EC7C9DB67BA0329B6"
                + "C055BEDBD520BD925BB658E42E1E6B70C814126178AAA18FCE4B17FBC68A30EC"
                + "839D14887F921D296C2BE5AD27FB57DEB6688E2B3416D7FCB896814C63DED966";
        addDSAParamSpec(3072, 256, strP, strQ, strG);
    }

    private DSAParameterCache() {
    }

    // CHECKSTYLE:SKIP
    private static void addDSAParamSpec(final int plen, final int qlen, final String strP,
            final String strQ, final String strG) {
        DSAParameterSpec spec = new DSAParameterSpec(new BigInteger(strP, 16),
                new BigInteger(strQ, 16), new BigInteger(strG, 16));
        cache.put(plen + "-" + qlen, spec);
    }

    // CHECKSTYLE:SKIP
    public static DSAParameterSpec getDSAParameterSpec(int plength,
            int qlength, SecureRandom random) {
        DSAParameterSpec spec = cache.get(plength + "-" + qlength);
        if (spec != null) {
            return new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
        }

        return getNewDSAParameterSpec(plength, qlength, random);
    }

    // CHECKSTYLE:SKIP
    public static DSAParameterSpec getNewDSAParameterSpec(final int plength, final int qlength,
            final SecureRandom random) {
        final int certainty = 80;
        SecureRandom tmpRandom = (random == null) ? new SecureRandom() : random;
        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                plength, qlength, certainty, tmpRandom);
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();
        return new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
    }

}
