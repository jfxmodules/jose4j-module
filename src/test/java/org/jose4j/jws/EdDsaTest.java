package org.jose4j.jws;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EdDsaKeyUtil;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


public class EdDsaTest
{
    @BeforeClass
    public static void check()
    {
        // skip these tests if EdDSA isn't available (i.e. before Java 17)
        org.junit.Assume.assumeTrue(new EdDsaKeyUtil().isAvailable());
    }

    @Test
    public void rfc8037appendixA1to5() throws Exception
    {
        // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.1

        String jwkJson = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
                "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"," +
                "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);
        String jkt = jwk.calculateBase64urlEncodedThumbprint("SHA-256");
        Assert.assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", jkt);

        JsonWebSignature jwsSigner = new JsonWebSignature();
        jwsSigner.setAlgorithmHeaderValue(AlgorithmIdentifiers.EDDSA);
        jwsSigner.setPayload("Example of Ed25519 signing");
        jwsSigner.setKey(jwk.getPrivateKey());
        String jws = jwsSigner.getCompactSerialization();

        String expectedJws = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCj" +
                "P0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

        Assert.assertEquals(expectedJws, jws);

        String jwkJsonPubOnly = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
        PublicJsonWebKey jwkPubOnly = PublicJsonWebKey.Factory.newPublicJwk(jwkJsonPubOnly);
        String jktPublicOnly = jwkPubOnly.calculateBase64urlEncodedThumbprint("SHA-256");
        Assert.assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", jktPublicOnly);

        JsonWebSignature jwsVerifier = new JsonWebSignature();
        jwsVerifier.setCompactSerialization(expectedJws);
        jwsVerifier.setKey(jwkPubOnly.getPublicKey());
        boolean okay = jwsVerifier.verifySignature();
        Assert.assertTrue(okay);
        Assert.assertEquals("Example of Ed25519 signing", jwsVerifier.getPayload());

        String alteredJws = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCj" +
                "X0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

        jwsVerifier = new JsonWebSignature();
        jwsVerifier.setCompactSerialization(alteredJws);
        jwsVerifier.setKey(jwkPubOnly.getPublicKey());
        okay = jwsVerifier.verifySignature();
        Assert.assertFalse(okay);
    }

    @Test
    public void verifyProducedElsewhere() throws JoseException
    {
        // JWS created using Nimbus which uses Tink for EdDSA
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"sipir4_DXRPiq3vgQPbX5EIZjhdxFVO0bwcVnIFZxQA\"}");
        String jws = "eyJhbGciOiJFZERTQSJ9.bWVo.BieQMHmbP-qyMnrbUV_mySYcoDqaxTrQGkGOZ5KGcAZ_8uwwSlds62O8yeHvp5sc4FnEas8XbJilf3-FQbQrAQ";

        // verify the signature
        JsonWebSignature jwsObject = new JsonWebSignature();
        jwsObject.setCompactSerialization(jws);
        jwsObject.setKey(jwk.getPublicKey());
        Assert.assertTrue(jwsObject.verifySignature());
        Assert.assertEquals("meh", jwsObject.getPayload());

        // reproduce the JWS, which works b/c EdDSA is deterministic
        jwk = PublicJsonWebKey.Factory.newPublicJwk(
                "{\"kty\":\"OKP\",\"d\":\"-g8nVY3FlaY9SNE1c5Edn6kQXXQN13SVLCmdlKYgqYM\"," +
                        "\"crv\":\"Ed25519\",\"x\":\"sipir4_DXRPiq3vgQPbX5EIZjhdxFVO0bwcVnIFZxQA\"}");
        jwsObject = new JsonWebSignature();
        jwsObject.setAlgorithmHeaderValue(AlgorithmIdentifiers.EDDSA);
        jwsObject.setKey(jwk.getPrivateKey());
        jwsObject.setPayload("meh");
        Assert.assertEquals(jws, jwsObject.getCompactSerialization());
    }

    @Test
    public void ed25519RoundTripGenKeys() throws JoseException
    {
        EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
        KeyPair keyPair1 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED25519);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED25519);
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("Little Ed", AlgorithmIdentifiers.EDDSA, priv1, pub1, priv2, pub2);
    }

    @Test
    public void ed448RoundTripGenKeys() throws JoseException
    {
        EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
        KeyPair keyPair1 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("Big Ed", AlgorithmIdentifiers.EDDSA, priv1, pub1, priv2, pub2);
    }

    @Test
    public void edMixedRoundTripGenKeys() throws JoseException
    {
        EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
        KeyPair keyPair1 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED25519);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("Cousin Eddie", AlgorithmIdentifiers.EDDSA, priv1, pub1, priv2, pub2);
    }
}
