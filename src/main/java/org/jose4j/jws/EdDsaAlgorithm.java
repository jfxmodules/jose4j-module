package org.jose4j.jws;

import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.lang.InvalidKeyException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

public class EdDsaAlgorithm extends BaseSignatureAlgorithm
{
    public EdDsaAlgorithm()
    {
        super(AlgorithmIdentifiers.EDDSA, "EdDSA", OctetKeyPairJsonWebKey.KEY_TYPE);
    }

    @Override
    public void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException
    {
        KeyValidationSupport.castKey(privateKey, EdECPrivateKey.class);
    }

    @Override
    public void validatePublicKey(PublicKey publicKey) throws InvalidKeyException
    {
        KeyValidationSupport.castKey(publicKey, EdECPublicKey.class);
    }
}
