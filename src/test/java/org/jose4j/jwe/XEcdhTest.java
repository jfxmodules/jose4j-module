package org.jose4j.jwe;

import org.jose4j.jca.ProviderContextTest;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.XDHKeyUtil;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;

import static org.junit.Assert.*;

public class XEcdhTest
{
    @BeforeClass
    public static void check()
    {
        // skip these tests if XDH isn't available (before java 11 I think)
        org.junit.Assume.assumeTrue(new XDHKeyUtil().isAvailable());
    }

    @Test
    public void rfc8037appendixA6() throws Exception
    {
        // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.6

        String jwkJsonToEncryptTo = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"kid\":\"Bob\",\n" +
                "   \"x\":\"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\"}";
        PublicJsonWebKey recipientPublicJwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJsonToEncryptTo);

        String ephemeralPublicJwkJson = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\n" +
                "   \"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}";
        PublicJsonWebKey ephemeralPublicJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralPublicJwkJson);

        byte[] ephemeralPrivateKeyBytes = new byte[] {119, 7, 109, 10, 115, 24, -91, 125, 60, 22, -63, 114, 81,
                -78, 102, 69, -33, 76, 47, -121, -21, -64, -103, 42, -79, 119, -5, -91, 29, -71, 44, 42};

        XDHKeyUtil keyUtil = new XDHKeyUtil();
        XECPrivateKey ephemeralPrivateKey = keyUtil.privateKey(ephemeralPrivateKeyBytes, XDHKeyUtil.X25519);
        KeyAgreement xka = KeyAgreement.getInstance("XDH");
        xka.init(ephemeralPrivateKey);
        PublicKey recipientPublicKey = recipientPublicJwk.getPublicKey();
        xka.doPhase(recipientPublicKey, true);
        byte[] dhz = xka.generateSecret();
        byte[] expectedZ = new byte[] {74, 93, -99, 91, -92, -50, 45, -31, 114, -114, 59, -12, -128, 53, 15, 37,
                -32, 126, 33, -55, 71, -47, -98, 51, 118, -16, -101, 60, 30, 22, 23, 66};

        Assert.assertArrayEquals(expectedZ, dhz);

        PublicJsonWebKey ephemeralJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralPublicJwkJson);
        ephemeralJwk.setPrivateKey(ephemeralPrivateKey);

        String ephemeralBothJwkJson = ephemeralJwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        PublicJsonWebKey parsedAgainEphemeralBothJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralBothJwkJson);
        Assert.assertEquals(parsedAgainEphemeralBothJwk.getPrivateKey(), ephemeralPrivateKey);
        Assert.assertEquals(parsedAgainEphemeralBothJwk.getPublicKey(), ephemeralPublicJwk.getPublicKey());

        PublicJsonWebKey recipientPublicJwkAgain = PublicJsonWebKey.Factory.newPublicJwk(recipientPublicKey);
        Assert.assertEquals(recipientPublicJwkAgain.getPublicKey(), recipientPublicKey);

        Headers headers = new Headers();
        headers.setStringHeaderValue(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithmIdentifiers.ECDH_ES);
        headers.setStringHeaderValue(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);

        EcdhKeyAgreementAlgorithm ecdhKeyAgreementAlgorithm = new EcdhKeyAgreementAlgorithm();

        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(32, AesKey.ALGORITHM);

        PublicKey pubKey = recipientPublicJwk.getPublicKey();
        ContentEncryptionKeys contentEncryptionKeys = ecdhKeyAgreementAlgorithm.manageForEncrypt(pubKey, cekDesc, headers, ephemeralJwk, ProviderContextTest.EMPTY_CONTEXT);

        byte[] contentEncryptionKey = contentEncryptionKeys.getContentEncryptionKey();
        assertEquals(32, contentEncryptionKey.length);

        // this is the result of the kdf run on expectedZ
        byte[] expectedDerivedKey = new byte[] {1, 58, 82, 48, 107, 105, 26, -77, 101, 111, -5, 111, -25, -69, 63, 6,
                -87, -16, 37, 3, 90, -96, -91, -38, -26, 29, -120, 87, -68, 99, -11, -6};

        assertArrayEquals(expectedDerivedKey, contentEncryptionKey);
    }

    @Test
    public void rfc8037appendixA7() throws Exception
    {
        // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.7

        String jwkJsonToEncryptTo = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\n" +
                "   \"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
        PublicJsonWebKey recipientPublicJwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJsonToEncryptTo);

        String ephemeralPublicJwkJson = "{\"kty\":\"OKP\",\"crv\":\"X448\",\n" +
                "   \"x\":\"mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A\"}";
        PublicJsonWebKey ephemeralPublicJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralPublicJwkJson);

        byte[] ephemeralPrivateKeyBytes = new byte[] {-102, -113, 73, 37, -47, 81, -97, 87, 117, -49, 70, -80, 75,
                88, 0, -44, -18, -98, -24, -70, -24, -68, 85, 101, -44, -104, -62, -115, -39, -55, -70, -11, 116,
                -87, 65, -105, 68, -119, 115, -111, 0, 99, -126, -90, -15, 39, -85, 29, -102, -62, -40, -64, -91,
                -104, 114, 107};

        XDHKeyUtil keyUtil = new XDHKeyUtil();
        XECPrivateKey ephemeralPrivateKey = keyUtil.privateKey(ephemeralPrivateKeyBytes, XDHKeyUtil.X448);
        KeyAgreement xka = KeyAgreement.getInstance("XDH");
        xka.init(ephemeralPrivateKey);
        PublicKey recipientPublicKey = recipientPublicJwk.getPublicKey();
        xka.doPhase(recipientPublicKey, true);
        byte[] dhz = xka.generateSecret();
        byte[] expectedZ = new byte[] {7, -1, -12, 24, 26, -58, -52, -107, -20, 28, 22, -87, 74, 15, 116, -47, 45,
                -94, 50, -50, 64, -89, 117, 82, 40, 29, 40, 43, -74, 12, 11, 86, -3, 36, 100, -61, 53, 84, 57, 54,
                82, 28, 36, 64, 48, -123, -43, -102, 68, -102, 80, 55, 81, 74, -121, -99};

        Assert.assertArrayEquals(expectedZ, dhz);

        PublicJsonWebKey ephemeralJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralPublicJwkJson);
        ephemeralJwk.setPrivateKey(ephemeralPrivateKey);

        String ephemeralBothJwkJson = ephemeralJwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        PublicJsonWebKey parsedAgainEphemeralBothJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralBothJwkJson);
        Assert.assertEquals(parsedAgainEphemeralBothJwk.getPrivateKey(), ephemeralPrivateKey);
        Assert.assertEquals(parsedAgainEphemeralBothJwk.getPublicKey(), ephemeralPublicJwk.getPublicKey());

        PublicJsonWebKey recipientPublicJwkAgain = PublicJsonWebKey.Factory.newPublicJwk(recipientPublicKey);
        Assert.assertEquals(recipientPublicJwkAgain.getPublicKey(), recipientPublicKey);

        Headers headers = new Headers();
        headers.setStringHeaderValue(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithmIdentifiers.ECDH_ES);
        headers.setStringHeaderValue(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);

        EcdhKeyAgreementAlgorithm ecdhKeyAgreementAlgorithm = new EcdhKeyAgreementAlgorithm();

        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(64, AesKey.ALGORITHM);

        PublicKey pubKey = recipientPublicJwk.getPublicKey();
        ContentEncryptionKeys contentEncryptionKeys = ecdhKeyAgreementAlgorithm.manageForEncrypt(pubKey, cekDesc, headers, ephemeralJwk, ProviderContextTest.EMPTY_CONTEXT);

        byte[] contentEncryptionKey = contentEncryptionKeys.getContentEncryptionKey();
        assertEquals(64, contentEncryptionKey.length);

        // this is the result of the kdf run on expectedZ
        byte[] expectedDerivedKey = new byte[] {48, 93, -30, -109, 3, -108, -2, -5, -114, -25, -119, -47, 12, -73,
                -63, 85, -12, -53, -14, -22, 7, -62, 56, 96, -99, 13, -120, -124, -4, 26, -99, -57, 2, -116, 109,
                73, -54, 80, -88, -77, 123, -68, -49, -112, -122, 34, 63, -20, 127, 69, -51, -68, 62, -19, 68, 106,
                3, -26, -24, -10, 122, 120, -27, -40};

        assertArrayEquals(expectedDerivedKey, contentEncryptionKey);
    }

    @Test
    public void extraCookbook() throws JoseException
    {
        // example content from
        // https://github.com/ietf-jose/cookbook/blob/master/curve25519/ecdh-es.json

        String jwkJson =
                "{\n" +
                "  \"kty\": \"OKP\",\n" +
                "  \"kid\": \"Bob\",\n" +
                "  \"use\": \"enc\",\n" +
                "  \"crv\": \"X25519\",\n" +
                "  \"x\": \"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\",\n" +
                "  \"d\": \"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os\"\n" +
                "}";
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);

        String jweString =
            "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoiQm9iIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ" +
            "4dlhIaDNRMlM0Vm90WGdCZGRHV0RfS2huellaX2V1QjJlYWVrTHZ2QURVIn0sImVuYyI6IkExMjhHQ00ifQ..0tCoBvRfolezYjpJ." +
            "cX3qZ4cfxiyr_Leem1b69MeLo-BHsMJy6RetGse91pgXjR7X87k1e7dJliYfzgseMV9dcVo3i1cAPeU2jkDCxrjxIBW0iUlF3JfkVH7" +
            "DU3B8GxzkblOJKwJE58Sd0rJEN9rSwfLf66sbTiY_vGYf7cZhbWhj6wwBnICFfaRh_2NubCdma7zX_vsdaGJXHn-6-jjR9UaQUbJD-t" +
            "Pn5UAW8Sa9lPAcncYZywscUM-FET3tePOH2h_xv_LFGuN2KYJ3BED_Eyo--oSX17DD7ksSt0wfzy_TWczaG1E_TWn4nvP6T6d5nMp9O" +
            "dfLWQNopQHoQGWlPbaRLHCk2mNl1K5GsJ6Q4tjSdFWpqRDpQUz2eYAk" +
            ".Yd4jUyp_PC5cACOwaAGwUQ";

        String expected = "You can trust us to stick with you through thick and thin–to the bitter end." +
                " And you can trust us to keep any secret of yours–closer than you keep it yourself." +
                " But you cannot trust us to let you face trouble alone, and go off without a word." +
                " We are your friends, Frodo.";

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(jwk.getPrivateKey());
        jwe.setCompactSerialization(jweString);
        assertEquals(expected, jwe.getPayload());
    }

    @Test
    public void roundTripJweX25519() throws Exception
    {
        OctetKeyPairJsonWebKey recipientJwk = OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519);

        System.out.println(recipientJwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        JsonWebEncryption jweObj = new JsonWebEncryption();
        jweObj.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        jweObj.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jweObj.setPayload("A donut with no hole is a danish");
        jweObj.setKey(recipientJwk.getPublicKey());
        String jwe = jweObj.getCompactSerialization();

        System.out.println(jwe);

        jweObj = new JsonWebEncryption();
        jweObj.setKey(recipientJwk.getPrivateKey());
        jweObj.setCompactSerialization(jwe);
        String payload = jweObj.getPayload();
        assertEquals("A donut with no hole is a danish", payload);
    }

    @Test
    public void roundTripJweX448() throws Exception
    {
        OctetKeyPairJsonWebKey recipientJwk = OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X448);

        JsonWebEncryption jweObj = new JsonWebEncryption();
        jweObj.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        jweObj.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jweObj.setPayload("Whoa, did somebody step on a duck?");
        jweObj.setKey(recipientJwk.getPublicKey());
        String jwe = jweObj.getCompactSerialization();
        System.out.println(jwe);
        jweObj = new JsonWebEncryption();
        jweObj.setKey(recipientJwk.getPrivateKey());
        jweObj.setCompactSerialization(jwe);
        String payload = jweObj.getPayload();
        assertEquals("Whoa, did somebody step on a duck?", payload);
    }

    @Test
    public void consumeProducedElsewhere() throws JoseException
    {
        // JWE created using Nimbus which uses Tink for XDH
        String jweString = "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6Ii1Pbm9qa0t0X2VjMWVYX2FXTkx3RG5" +
                "ndFhJRDBWNHJpbE5nZjRUYW1vbWMifSwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImFsZyI6IkVDREgtRVMifQ..n0a0IzC6I" +
                "9O112_8_fq_RA.1ERfdkKoltne7Un7eEI8jA.c1z4C6K_9PrYoq9iYwTckg";
        String jwkJson = "{\"kty\":\"OKP\",\"d\":\"zybXOI1wLTDCz751YDh_vL_U94IHQnswlShdEkPDsJU\"," +
                "\"crv\":\"X25519\",\"x\":\"IZmhuDcUtycL0hFFpoVQ-iCje4RWZCfnuclMayw_KQQ\"}";

        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(jwk.getPrivateKey());
        jwe.setCompactSerialization(jweString);
        assertEquals("meh", jwe.getPlaintextString());
    }
}
