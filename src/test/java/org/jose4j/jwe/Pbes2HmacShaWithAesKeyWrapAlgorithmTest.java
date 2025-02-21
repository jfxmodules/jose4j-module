/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwe;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContextTest;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwt.consumer.SimpleJwtConsumerTestHelp;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import java.security.Key;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;
import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.*;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.RSA1_5;
import static org.junit.Assert.*;

/**
 */
public class Pbes2HmacShaWithAesKeyWrapAlgorithmTest
{
    // per http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#section-4.8.1.2
    // "A minimum iteration count of 1000 is RECOMMENDED."
    public static final int MINIMUM_ITERATION_COUNT = 1000;

    // per tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#section-4.8.1.1
    // "A Salt Input value containing 8 or more octets MUST be used"
    public static final int MINIMUM_SALT_BYTE_LENGTH = 8;

    @Test
    public void combinationOfRoundTrips() throws Exception
    {
        String[] algs = new String[] {PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS256_A128KW};
        String[] encs = new String[] {AES_128_CBC_HMAC_SHA_256, AES_192_CBC_HMAC_SHA_384, AES_256_CBC_HMAC_SHA_512};

        String password = "password";
        String plaintext = "<insert some witty quote or remark here>";

        for (String alg : algs)
        {
            for (String enc : encs)
            {
                JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
                encryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, algs));
                encryptingJwe.setAlgorithmHeaderValue(alg);
                encryptingJwe.setEncryptionMethodHeaderParameter(enc);
                encryptingJwe.setPayload(plaintext);
                encryptingJwe.setKey(new PbkdfKey(password));
                String compactSerialization = encryptingJwe.getCompactSerialization();

                JsonWebEncryption decryptingJwe = new JsonWebEncryption();
                decryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, algs));
                decryptingJwe.setCompactSerialization(compactSerialization);
                decryptingJwe.setKey(new PbkdfKey(password));
                assertThat(plaintext, equalTo(decryptingJwe.getPayload()));
            }
        }
    }

    @Test (expected = InvalidKeyException.class)
    public void testNullKey() throws JoseException
    {
        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS256_A128KW);
        encryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW));
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        encryptingJwe.setPayload("meh");

        encryptingJwe.getCompactSerialization();
    }

    @Test
    public void testDefaultsMeetMinimumRequiredOrSuggested() throws JoseException
    {
        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS256_A128KW);
        encryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW));
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        encryptingJwe.setPayload("meh");
        PbkdfKey key = new PbkdfKey("passtheword");
        encryptingJwe.setKey(key);
        String compactSerialization = encryptingJwe.getCompactSerialization();
        System.out.println(compactSerialization);

        JsonWebEncryption decryptingJwe = new JsonWebEncryption();
        decryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW));
        decryptingJwe.setCompactSerialization(compactSerialization);
        decryptingJwe.setKey(key);
        decryptingJwe.getPayload();
        Headers headers = decryptingJwe.getHeaders();

        Long iterationCount = headers.getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        assertTrue(iterationCount >= MINIMUM_ITERATION_COUNT);

        String saltInputString = headers.getStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT);
        Base64Url b = new Base64Url();
        byte[] saltInput = b.base64UrlDecode(saltInputString);
        assertTrue(saltInput.length >= MINIMUM_SALT_BYTE_LENGTH);
    }

    @Test
    public void testUsingAndSettingDefaults() throws JoseException
    {
        Pbes2HmacShaWithAesKeyWrapAlgorithm pbes2 = new Pbes2HmacShaWithAesKeyWrapAlgorithm.HmacSha256Aes128();

        assertTrue(pbes2.getDefaultIterationCount() >= MINIMUM_ITERATION_COUNT);
        assertTrue(pbes2.getDefaultSaltByteLength() >= MINIMUM_SALT_BYTE_LENGTH);

        PbkdfKey key = new PbkdfKey("a password");

        Headers headers = new Headers();
        Key derivedKey = pbes2.deriveForEncrypt(key, headers, ProviderContextTest.EMPTY_CONTEXT);
        assertThat(derivedKey.getEncoded().length, equalTo(16));

        String saltInputString = headers.getStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT);
        byte[] saltInput = Base64Url.decode(saltInputString);
        assertThat(saltInput.length, equalTo(pbes2.getDefaultSaltByteLength()));
        Long iterationCount = headers.getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        assertThat(iterationCount, equalTo(pbes2.getDefaultIterationCount()));

        Pbes2HmacShaWithAesKeyWrapAlgorithm newPbes2 = new Pbes2HmacShaWithAesKeyWrapAlgorithm.HmacSha256Aes128();
        long newDefaultIterationCount = 1024;
        newPbes2.setDefaultIterationCount(newDefaultIterationCount);

        int newDefaultSaltByteLength = 16;
        newPbes2.setDefaultSaltByteLength(newDefaultSaltByteLength);

        headers = new Headers();
        derivedKey = newPbes2.deriveForEncrypt(key, headers, ProviderContextTest.EMPTY_CONTEXT);
        saltInputString = headers.getStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT);
        saltInput = Base64Url.decode(saltInputString);
        assertThat(saltInput.length, equalTo(newDefaultSaltByteLength));
        iterationCount = headers.getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        assertThat(iterationCount, equalTo(newDefaultIterationCount));

        assertThat(derivedKey.getEncoded().length, equalTo(16));
    }

    @Test
    public void testSettingSaltAndIterationCount() throws JoseException
    {
        String password = "secret word";
        String plaintext = "<insert some witty quote or remark here, again>";

        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        int saltByteLength = 32;
        String saltInputString = Base64Url.encode(ByteUtil.randomBytes(saltByteLength));
        encryptingJwe.getHeaders().setStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT, saltInputString);
        long iterationCount = 1024L;
        encryptingJwe.setHeader(HeaderParameterNames.PBES2_ITERATION_COUNT, iterationCount);

        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS384_A192KW);
        encryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW));
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_192_CBC_HMAC_SHA_384);
        encryptingJwe.setPayload(plaintext);
        encryptingJwe.setKey(new PbkdfKey(password));
        String compactSerialization = encryptingJwe.getCompactSerialization();

        JsonWebEncryption decryptingJwe = new JsonWebEncryption();
        decryptingJwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW));
        decryptingJwe.setCompactSerialization(compactSerialization);
        decryptingJwe.setKey(new PbkdfKey(password));
        assertThat(plaintext, equalTo(decryptingJwe.getPayload()));

        String saltInputStringFromHeader = decryptingJwe.getHeader(HeaderParameterNames.PBES2_SALT_INPUT);
        assertThat(saltInputString, equalTo(saltInputStringFromHeader));
        assertThat(saltByteLength, equalTo(Base64Url.decode(saltInputStringFromHeader).length));
        long iterationCountFromHeader = decryptingJwe.getHeaders().getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        assertThat(iterationCount, equalTo(iterationCountFromHeader));
    }


    @Test (expected = JoseException.class)
    public void testTooSmallIterationCountRejected() throws JoseException
    {
        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        encryptingJwe.setHeader(HeaderParameterNames.PBES2_ITERATION_COUNT, 918L);
        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS256_A128KW);
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        encryptingJwe.setPayload("some text");
        encryptingJwe.setKey(new PbkdfKey("super secret word"));
        encryptingJwe.getCompactSerialization();
    }

    @Test (expected = JoseException.class)
    public void testTooLittleSaltRejected() throws JoseException
    {
        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        encryptingJwe.setHeader(HeaderParameterNames.PBES2_SALT_INPUT, "bWVo");
        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS256_A128KW);
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        encryptingJwe.setPayload("some text");
        encryptingJwe.setKey(new PbkdfKey("super secret word"));
        encryptingJwe.getCompactSerialization();
    }

    @Test
    public void p2cTooBig() throws InvalidJwtException, MalformedClaimException
    {
        // check that default protections are in place for the "Billion hashes attack" from
        // https://i.blackhat.com/BH-US-23/Presentations/US-23-Tervoort-Three-New-Attacks-Against-JSON-Web-Tokens-whitepaper.pdf

        // PBES2-HS256+A128KW
        String jwe1 = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3h" +
                "jaFl6NlpaY0hBIiwicDJjIjoyMTQ3NDgzNjQ3LCJlbmMiOiJBMTI4Q0JDLUhTMj" +
                "U2In0.YKbKLsEoyw_JoNvhtuHo9aaeRNSEhhAW2OVHcuF_HLqS0n6hA_fgCA.VB" +
                "iCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJ" +
                "LZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYC" +
                "NA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3" +
                "dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL9" +
                "3R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzX" +
                "FFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrc" +
                "D_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywI" +
                "yzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0" +
                "TuSE8oMKdTw8V3kobXZ77ulMwDs4p.ALTKwxvAefeL-32NY7eTAQ";

        // PBES2-HS512+A256KW
        String jwe2 = "eyJwMmMiOjI1MDAwMDAsImFsZyI6IlBCRVMyLUhTNTEyK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLC" +
                "JwMnMiOiJGbVE0aDY1aUFlZEs0SUFyIn0._P2Mbn0nvqRZVCaEaLnKQkMFwGNmEVbm8Ffnb5uIas0iAt5wcWC3T7rdTw" +
                "yliWW11YnhpaiXH0WRalAsIUyaVHC4Ku1j9bVP.Tg2KOblqWEF9iC71O-WgBw.OCjt9WYrTFMIst7XBZ8HeA.YRqs3_n" +
                "MchYr39AJYquQs8-PrZa2NGuqshOvtLfWSvE";

        // PBES2-HS384+A192KW
        String jwe3 = "eyJwMmMiOjI1MDAwMDAsImFsZyI6IlBCRVMyLUhTMzg0K0ExOTJLVyIsImVuYyI6IkExOTJDQkMtSFMzODQiLC" +
                "JwMnMiOiJneXBKYzJFVXNtbmNqTUtqIn0.RYXJhCW2m4Pa5XPUPVVQVJRg8z-jj-zyXoa-Q1JzdfjO2tvrELM7Ko3qhk" +
                "v2WcUAw3ZagzIeNjY.FhNCr7zjUt0fA6KotCbdUw.DMYLybjcrOX9cfwdWaORLg.QCGY9clkv4sz1rZeexg2dUx4ViH-BeL7\n";

        for (String jwt : new String[] {jwe1, jwe2, jwe3})
        {
            // PBE2 algs blocked by default
            JwtConsumer c = new JwtConsumerBuilder()
                    .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey())
                    .build();

            SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, c);

            // but also there's a max on the # of iterations
            c = new JwtConsumerBuilder()
                    .setDecryptionKey(new PbkdfKey("super secret word"))
                    .setJweAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                    .build();

            SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, c);
        }
    }

}
