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

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.IntegrityException;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 */
public abstract class WrappingKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    protected final Logger log = LoggerFactory.getLogger(getClass());

    private AlgorithmParameterSpec algorithmParameterSpec;
    protected boolean useSuppliedKeyProviderContext = true;

    public WrappingKeyManagementAlgorithm(String javaAlg, String alg)
    {
        setJavaAlgorithm(javaAlg);
        setAlgorithmIdentifier(alg);
    }

    public void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec)
    {
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        byte[] contentEncryptionKey = cekOverride == null ? ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength()) : cekOverride;
        return manageForEnc(managementKey, cekDesc, contentEncryptionKey, providerContext);
    }

    protected ContentEncryptionKeys manageForEnc(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, byte[] contentEncryptionKey, ProviderContext providerContext) throws JoseException
    {
        ProviderContext.Context ctx = chooseContext(providerContext);
        String provider = ctx.getCipherProvider();

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm(), provider);

        try
        {
            initCipher(cipher, Cipher.WRAP_MODE, managementKey);
            String contentEncryptionKeyAlgorithm = cekDesc.getContentEncryptionKeyAlgorithm();
            byte[] encryptedKey = cipher.wrap(new SecretKeySpec(contentEncryptionKey, contentEncryptionKeyAlgorithm));
            return new ContentEncryptionKeys(contentEncryptionKey, encryptedKey);
        }
        catch  (InvalidKeyException e)
        {
            throw new org.jose4j.lang.InvalidKeyException("Unable to encrypt ("+cipher.getAlgorithm()+") the Content Encryption Key: " + e, e);
        }
        catch (IllegalBlockSizeException | InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Unable to encrypt ("+cipher.getAlgorithm()+") the Content Encryption Key: " + e, e);
        }
    }

    void initCipher(Cipher cipher, int mode, Key key) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (algorithmParameterSpec == null)
        {
            cipher.init(mode, key);
        }
        else
        {
            cipher.init(mode, key, algorithmParameterSpec);
        }
    }

    @Override
    public CryptoPrimitive prepareForDecrypt(Key managementKey, Headers headers, ProviderContext providerContext) throws JoseException
    {
        ProviderContext.Context ctx = chooseContext(providerContext);
        String provider = ctx.getCipherProvider();
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm(), provider);

        int mode = ctx.getKeyDecipherModeOverride() == ProviderContext.KeyDecipherMode.DECRYPT ? Cipher.DECRYPT_MODE :  Cipher.UNWRAP_MODE;

        try
        {
            initCipher(cipher, mode, managementKey);
        }
        catch  (InvalidKeyException e)
        {
            throw new org.jose4j.lang.InvalidKeyException("Unable to initialize cipher ("+cipher.getAlgorithm()+") for key unwrap/decrypt - " + e, e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Unable to initialize cipher ("+cipher.getAlgorithm()+") for key unwrap/decrypt - " + e, e);
        }

        return new CryptoPrimitive(cipher);
    }

    private ProviderContext.Context chooseContext(ProviderContext providerContext)
    {
        return useSuppliedKeyProviderContext ? providerContext.getSuppliedKeyProviderContext() : providerContext.getGeneralProviderContext();
    }

    public Key manageForDecrypt(CryptoPrimitive cryptoPrimitive, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext) throws JoseException
    {
        try
        {
            return unwrap(cryptoPrimitive, encryptedKey, providerContext, cekDesc);
        }
        catch (Exception e)
        {
            throw new IntegrityException(getAlgorithmIdentifier() + " key unwrap/decrypt failed.", e);
        }
    }

    protected Key unwrap(CryptoPrimitive cryptoPrimitive, byte[] encryptedKey, ProviderContext providerContext,  ContentEncryptionKeyDescriptor cekDesc)
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        ProviderContext.Context ctx = chooseContext(providerContext);
        Cipher cipher = cryptoPrimitive.getCipher();
        String cekAlg = cekDesc.getContentEncryptionKeyAlgorithm();
        if (ctx.getKeyDecipherModeOverride() == ProviderContext.KeyDecipherMode.DECRYPT)
        {
            byte[] clear = cipher.doFinal(encryptedKey);
            return new SecretKeySpec(clear, cekAlg);
        }
        else
        {
            return cipher.unwrap(encryptedKey, cekAlg, Cipher.SECRET_KEY);
        }
    }
}
