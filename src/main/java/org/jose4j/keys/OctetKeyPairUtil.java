package org.jose4j.keys;

import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;

abstract public class OctetKeyPairUtil extends KeyPairUtil
{
    public OctetKeyPairUtil(String provider, SecureRandom secureRandom)
    {
        super(provider, secureRandom);
    }

    public static OctetKeyPairUtil getOctetKeyPairUtil(String subtypeName, String provider, SecureRandom secureRandom)
    {
        if (subtypeName.equals(OctetKeyPairJsonWebKey.SUBTYPE_ED25519) || subtypeName.equals(OctetKeyPairJsonWebKey.SUBTYPE_ED448))
        {
            return new EdDsaKeyUtil(provider, secureRandom);
        }
        else if (subtypeName.equals(OctetKeyPairJsonWebKey.SUBTYPE_X25519) || subtypeName.equals(OctetKeyPairJsonWebKey.SUBTYPE_X448))
        {
            return new XDHKeyUtil(provider, secureRandom);
        }

        return null;
    }

    abstract public PublicKey publicKey(byte[] publicKeyBytes, String name) throws JoseException;
    abstract public PrivateKey privateKey(byte[] privateKeyBytes, String name) throws JoseException;

    abstract public byte[] rawPublicKey(Key key);
    abstract public byte[] rawPrivateKey(PrivateKey privateKey);

    public KeyPair generateKeyPair(String name) throws JoseException
    {
        KeyPairGenerator keyGenerator = getKeyPairGenerator();
        NamedParameterSpec spec = getNamedParameterSpec(name);

        try
        {
            if (secureRandom == null)
            {
                keyGenerator.initialize(spec);
            }
            else
            {
                keyGenerator.initialize(spec, secureRandom);
            }
            return keyGenerator.generateKeyPair();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Unable to create EdDSA key pair: " + e, e);
        }
    }

    NamedParameterSpec getNamedParameterSpec(String name) throws JoseException
    {
        try
        {
            return new NamedParameterSpec(name);
        }
        catch (NoClassDefFoundError ncd)
        {
            throw new JoseException(name + " NamedParameterSpec not available. " + ExceptionHelp.toStringWithCauses(ncd));
        }
    }
}
