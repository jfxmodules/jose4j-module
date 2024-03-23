package org.jose4j.keys;

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;

public class EdDsaKeyUtil extends OctetKeyPairUtil
{
    public static final String ED25519 = "Ed25519";
    public static final String ED448 = "Ed448";

    private static final byte BYTE_01111111 = (byte)127;
    private static final byte BYTE_10000000 = (byte)-128;
    private static final byte BYTE_00000000 = (byte)0;

    public EdDsaKeyUtil()
    {
        this(null, null);
    }

    public EdDsaKeyUtil(String provider, SecureRandom secureRandom)
    {
        super(provider, secureRandom);
    }

    @Override
    String getAlgorithm()
    {
        return "EDDSA";
    }

    public byte[] rawPublicKey(Key key)
    {
        EdECPublicKey edECPublicKey = (EdECPublicKey) key;
        EdECPoint edEdPoint = edECPublicKey.getPoint();
        BigInteger y = edEdPoint.getY();
        byte[] yBytes = y.toByteArray();
        byte[] yReversedBytes = ByteUtil.reverse(yBytes);
        int byteLen = edECPublicKey.getParams().getName().equals(ED25519) ? 32 : 57; // Ed25519 / Ed448
        if (yReversedBytes.length != byteLen)
        {
            yReversedBytes = Arrays.copyOf(yReversedBytes, byteLen);
        }
        byte byteToOrWith = (edEdPoint.isXOdd() ? BYTE_10000000 : BYTE_00000000);
        yReversedBytes[yReversedBytes.length - 1] |= byteToOrWith;
        return yReversedBytes;
    }

    public byte[] rawPrivateKey(PrivateKey privateKey)
    {
        EdECPrivateKey edECPrivateKey = (EdECPrivateKey) privateKey;
        Optional<byte[]> optionalBytes = edECPrivateKey.getBytes();
        return optionalBytes.orElse(ByteUtil.EMPTY_BYTES);
    }

    @Override
    public EdECPublicKey publicKey(byte[] publicKeyBytes, String name) throws JoseException
    {
        publicKeyBytes = publicKeyBytes.clone();
        byte rightByte = publicKeyBytes[publicKeyBytes.length - 1];
        publicKeyBytes[publicKeyBytes.length - 1] &= BYTE_01111111;
        boolean xIsOdd = (rightByte & BYTE_10000000) != 0;
        publicKeyBytes = ByteUtil.reverse(publicKeyBytes);
        BigInteger y = BigEndianBigInteger.fromBytes(publicKeyBytes);

        NamedParameterSpec paramSpec = getNamedParameterSpec(name);
        EdECPoint ep = new EdECPoint(xIsOdd, y);
        EdECPublicKeySpec keySpec = new EdECPublicKeySpec(paramSpec, ep);

        try
        {
            PublicKey publicKey = getKeyFactory().generatePublic(keySpec);
            return (EdECPublicKey) publicKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new JoseException("Invalid key spec: " + e, e);
        }
    }

    @Override
    public EdECPrivateKey privateKey(byte[] privateKeyBytes, String name) throws JoseException
    {
        NamedParameterSpec paramSpec = getNamedParameterSpec(name);
        EdECPrivateKeySpec privateKeySpec = new EdECPrivateKeySpec(paramSpec, privateKeyBytes);
        try
        {
            PrivateKey privateKey = getKeyFactory().generatePrivate(privateKeySpec);
            return (EdECPrivateKey) privateKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new JoseException("Invalid key spec: " + e, e);
        }
    }

    static public boolean isEdECPublicKey(Key key)
    {
        try
        {
            return key instanceof EdECPublicKey;
        }
        catch (NoClassDefFoundError e)
        {
            return false;
        }
    }


    static public boolean isEdECPrivateKey(Key key)
    {
        try
        {
            return key instanceof EdECPrivateKey;
        }
        catch (NoClassDefFoundError e)
        {
            return false;
        }
    }
}
