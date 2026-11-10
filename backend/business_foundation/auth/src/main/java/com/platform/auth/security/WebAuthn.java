package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 WebAuthn / Passkey 实现：CBOR 解析 + COSE 公钥转换 + 断言签名校验。
 */
public final class WebAuthn {
    private WebAuthn() {}

    public static Map<String, Object> registrationOptions(String rpId, String rpName, String identityId,
                                                          String username, String displayName,
                                                          List<String> excludeCredentialIds) {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("id", b64(identityId.getBytes(StandardCharsets.UTF_8)));
        user.put("name", username);
        user.put("displayName", displayName == null ? username : displayName);
        Map<String, Object> rp = new LinkedHashMap<>();
        rp.put("id", rpId);
        rp.put("name", rpName);
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", b64(randomBytes(32)));
        options.put("rp", rp);
        options.put("user", user);
        options.put("timeout", 120000);
        options.put("attestation", "none");
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),
                Map.of("type", "public-key", "alg", -257)));
        options.put("authenticatorSelection", Map.of("residentKey", "preferred", "userVerification", "preferred"));
        if (excludeCredentialIds != null && !excludeCredentialIds.isEmpty()) {
            options.put("excludeCredentials", excludeCredentialIds.stream()
                    .map(id -> Map.of("type", "public-key", "id", id)).toList());
        }
        return options;
    }

    public static Map<String, Object> assertionOptions(String rpId, String challenge, List<String> credentialIds) {
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challenge == null ? b64(randomBytes(32)) : challenge);
        options.put("rpId", rpId);
        options.put("timeout", 120000);
        options.put("userVerification", "preferred");
        if (credentialIds != null && !credentialIds.isEmpty()) {
            options.put("allowCredentials", credentialIds.stream()
                    .map(id -> Map.of("type", "public-key", "id", id)).toList());
        }
        return options;
    }

    public static Map<String, Object> register(String attestationObjectB64, String clientDataJsonB64,
                                               String expectedChallenge, String expectedOrigin, String rpId) {
        byte[] clientData = Base64.getUrlDecoder().decode(pad(clientDataJsonB64));
        Map<String, Object> clientJson = Json.readMap(new String(clientData, StandardCharsets.UTF_8));
        if (!"webauthn.create".equals(clientJson.get("type"))) {
            throw ApiException.badRequest("WebAuthn 注册类型无效");
        }
        if (!expectedChallenge.equals(clientJson.get("challenge"))) {
            throw ApiException.badRequest("WebAuthn challenge 不匹配");
        }
        String origin = String.valueOf(clientJson.get("origin"));
        if (!expectedOrigin.equals(origin)) {
            throw ApiException.badRequest("WebAuthn origin 不匹配");
        }
        byte[] attestation = Base64.getUrlDecoder().decode(pad(attestationObjectB64));
        Object decoded = Cbor.decode(attestation);
        if (!(decoded instanceof Map<?, ?> map)) {
            throw ApiException.badRequest("attestationObject 格式无效");
        }
        Object authDataObj = map.get("authData");
        if (!(authDataObj instanceof byte[] authData)) {
            throw ApiException.badRequest("attestationObject 缺少 authData");
        }
        int offset = 37;
        if (authData.length < 55) {
            throw ApiException.badRequest("authData 长度不足");
        }
        int credIdLen = ((authData[53] & 0xff) << 8) | (authData[54] & 0xff);
        if (authData.length < 55 + credIdLen) {
            throw ApiException.badRequest("authData 凭据长度无效");
        }
        byte[] credentialId = new byte[credIdLen];
        System.arraycopy(authData, 55, credentialId, 0, credIdLen);
        offset = 55 + credIdLen;
        byte[] coseBytes = new byte[authData.length - offset];
        System.arraycopy(authData, offset, coseBytes, 0, coseBytes.length);
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("credential_id", b64(credentialId));
        credential.put("public_key", convertCose(coseBytes));
        credential.put("sign_count", 0);
        return credential;
    }

    public static long verifyAssertion(Map<String, Object> credential, String authenticatorDataB64,
                                       String clientDataJsonB64, String signatureB64,
                                       String expectedChallenge, String expectedOrigin, String rpId) {
        byte[] clientData = Base64.getUrlDecoder().decode(pad(clientDataJsonB64));
        Map<String, Object> clientJson = Json.readMap(new String(clientData, StandardCharsets.UTF_8));
        if (!"webauthn.get".equals(clientJson.get("type"))) {
            throw ApiException.badRequest("WebAuthn 断言类型无效");
        }
        if (!expectedChallenge.equals(clientJson.get("challenge"))) {
            throw ApiException.badRequest("WebAuthn challenge 不匹配");
        }
        if (!expectedOrigin.equals(String.valueOf(clientJson.get("origin")))) {
            throw ApiException.badRequest("WebAuthn origin 不匹配");
        }
        byte[] authData = Base64.getUrlDecoder().decode(pad(authenticatorDataB64));
        if (authData.length < 37) {
            throw ApiException.badRequest("authenticatorData 无效");
        }
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        if (!MessageDigest.isEqual(rpIdHash, sha256(rpId))) {
            throw ApiException.badRequest("WebAuthn RP ID 不匹配");
        }
        long signCount = ((long) (authData[33] & 0xff) << 24) | ((authData[34] & 0xff) << 16)
                | ((authData[35] & 0xff) << 8) | (authData[36] & 0xff);
        byte[] clientHash = sha256(clientData);
        ByteArrayOutputStream signed = new ByteArrayOutputStream();
        signed.writeBytes(authData);
        signed.writeBytes(clientHash);
        try {
            PublicKey publicKey = decodePublicKey(String.valueOf(credential.get("public_key")));
            String algorithm = publicKey.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(signed.toByteArray());
            if (!verifier.verify(Base64.getUrlDecoder().decode(pad(signatureB64)))) {
                throw ApiException.badRequest("WebAuthn 签名校验失败");
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.badRequest("WebAuthn 签名校验失败");
        }
        long previous = credential.get("sign_count") instanceof Number n ? n.longValue() : 0;
        if (signCount > 0 && previous > 0 && signCount <= previous) {
            throw ApiException.badRequest("WebAuthn 签名计数器异常");
        }
        return signCount;
    }

    private static String convertCose(byte[] cose) {
        Object decoded = Cbor.decode(cose);
        if (!(decoded instanceof Map<?, ?> map)) {
            throw ApiException.badRequest("COSE 公钥格式无效");
        }
        try {
            Object kty = map.get(1);
            if (kty instanceof Number n && n.intValue() == 2) {
                byte[] x = (byte[]) map.get(-2);
                byte[] y = (byte[]) map.get(-3);
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec("secp256r1"));
                ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
                ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
                PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
                return b64(key.getEncoded());
            }
            if (kty instanceof Number n && n.intValue() == 3) {
                byte[] modulus = (byte[]) map.get(-1);
                byte[] exponent = (byte[]) map.get(-2);
                PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent)));
                return b64(key.getEncoded());
            }
        } catch (Exception e) {
            throw ApiException.badRequest("COSE 公钥解析失败");
        }
        throw ApiException.badRequest("不支持的 COSE 公钥类型");
    }

    private static PublicKey decodePublicKey(String encoded) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(
                    new X509EncodedKeySpec(Base64.getUrlDecoder().decode(pad(encoded))));
        } catch (Exception ignored) {
        }
        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(Base64.getUrlDecoder().decode(pad(encoded))));
        } catch (Exception e) {
            throw ApiException.badRequest("公钥解析失败");
        }
    }

    public static byte[] sha256(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception e) {
            throw ApiException.internal("摘要计算失败");
        }
    }

    public static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public static String randomChallenge() {
        return b64(randomBytes(32));
    }

    private static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        new java.security.SecureRandom().nextBytes(out);
        return out;
    }

    private static String pad(String value) {
        int remainder = value.length() % 4;
        if (remainder == 0) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value);
        while (sb.length() % 4 != 0) {
            sb.append('=');
        }
        return sb.toString();
    }

    /** 最小 CBOR 解码器（仅支持 WebAuthn 所需类型）。 */
    static final class Cbor {
        private final byte[] data;
        private int pos;

        private Cbor(byte[] data) {
            this.data = data;
        }

        static Object decode(byte[] data) {
            Cbor cbor = new Cbor(data);
            return cbor.read();
        }

        private Object read() {
            int initial = data[pos++] & 0xff;
            int major = initial >>> 5;
            int additional = initial & 0x1f;
            if (major == 7) {
                return switch (additional) {
                    case 20 -> Boolean.FALSE;
                    case 21 -> Boolean.TRUE;
                    case 22 -> null;
                    case 26 -> Float.intBitsToFloat((int) readUint(4));
                    case 27 -> Double.longBitsToDouble(readUint(8));
                    default -> {
                        long value = additional < 24 ? additional : readUint(additional - 24 + 1);
                        yield value;
                    }
                };
            }
            long value = additional < 24 ? additional
                    : additional == 24 ? readUint(1)
                    : additional == 25 ? readUint(2)
                    : additional == 26 ? readUint(4)
                    : additional == 27 ? readUint(8)
                    : -1;
            if (value < 0) {
                throw ApiException.badRequest("CBOR 数据无效");
            }
            int length = (int) value;
            return switch (major) {
                case 0 -> value;
                case 1 -> -1 - value;
                case 2 -> take(length);
                case 3 -> new String(take(length), StandardCharsets.UTF_8);
                case 4 -> {
                    List<Object> list = new ArrayList<>();
                    for (int i = 0; i < length; i++) {
                        list.add(read());
                    }
                    yield list;
                }
                case 5 -> {
                    Map<Object, Object> map = new LinkedHashMap<>();
                    for (int i = 0; i < length; i++) {
                        map.put(read(), read());
                    }
                    yield map;
                }
                case 6 -> read();
                default -> throw ApiException.badRequest("CBOR 类型不支持");
            };
        }

        private byte[] take(int length) {
            if (pos + length > data.length) {
                throw ApiException.badRequest("CBOR 长度越界");
            }
            byte[] out = new byte[length];
            System.arraycopy(data, pos, out, 0, length);
            pos += length;
            return out;
        }

        private long readUint(int bytes) {
            long value = 0;
            for (int i = 0; i < bytes; i++) {
                value = (value << 8) | (data[pos++] & 0xff);
            }
            return value;
        }
    }
}
