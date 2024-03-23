package org.jose4j.jwk;

import org.jose4j.keys.OctetKeyPairUtil;
import org.jose4j.lang.JoseException;

import java.security.KeyPair;
import java.security.SecureRandom;

public class OkpJwkGenerator
{
    public static OctetKeyPairJsonWebKey generateJwk(String subtype) throws JoseException
    {
        return generateJwk(subtype, null, null);
    }

    public static OctetKeyPairJsonWebKey generateJwk(String subtype, String provider, SecureRandom secureRandom)
            throws JoseException
    {
        OctetKeyPairUtil kpu = OctetKeyPairUtil.getOctetKeyPairUtil(subtype, provider, secureRandom);
        if (kpu == null)
        {
            throw new IllegalArgumentException("Cannot create OKP JWK. The subtype/crv \"" + subtype + "\" is unknown or unsupported.");
        }
        KeyPair kp = kpu.generateKeyPair(subtype);
        OctetKeyPairJsonWebKey okpJwk = (OctetKeyPairJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(kp.getPublic());
        okpJwk.setPrivateKey(kp.getPrivate());
        return okpJwk;
    }
}
