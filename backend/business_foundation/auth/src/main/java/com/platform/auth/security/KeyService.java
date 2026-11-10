package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class KeyService {
    private final Db db;
    private final CryptoBox crypto;
    private final AppProps props;
    private volatile RSAKey activeKey;
    private volatile String activeKid;

    public KeyService(Db db, CryptoBox crypto, AppProps props) {
        this.db = db;
        this.crypto = crypto;
        this.props = props;
    }

    public synchronized void ensureKey() {
        if (activeKey != null) {
            return;
        }
        List<Map<String, Object>> rows = db.list(
                "SELECT kid, private_key_encrypted FROM signing_keys WHERE status = 'active' ORDER BY created_at DESC LIMIT 1");
        if (!rows.isEmpty()) {
            Map<String, Object> row = rows.getFirst();
            try {
                JWK jwk = JWK.parseFromPEMEncodedObjects(crypto.decrypt(String.valueOf(row.get("private_key_encrypted"))));
                if (jwk instanceof RSAKey rsa) {
                    activeKey = rsa;
                    activeKid = String.valueOf(row.get("kid"));
                    return;
                }
            } catch (Exception e) {
                generate();
                return;
            }
        }
        generate();
    }

    private void generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            String kid = Ids.uuidStr();
            String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----";
            String publicPem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----";
            RSAKey rsa = new RSAKey.Builder((RSAPublicKey) pair.getPublic()).keyID(kid).build();
            db.update("INSERT INTO signing_keys (kid, algorithm, private_key_encrypted, public_pem, public_jwk) "
                            + "VALUES (:kid, 'RS256', :priv, :pub, :jwk)",
                    Db.params("kid", kid, "priv", crypto.encrypt(privatePem), "pub", publicPem,
                            "jwk", Json.jsonb(Json.readMap(rsa.toPublicJWK().toJSONString()))));
            activeKey = rsa;
            activeKid = kid;
        } catch (Exception e) {
            throw ApiException.internal("生成签名密钥失败");
        }
    }

    public RSAKey signingKey() {
        ensureKey();
        return activeKey;
    }

    public synchronized Map<String, Object> rotate() {
        ensureKey();
        db.update("UPDATE signing_keys SET status = 'retired', retired_at = now() WHERE status = 'active'",
                java.util.Map.of());
        activeKey = null;
        activeKid = null;
        ensureKey();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kid", activeKid);
        out.put("algorithm", "RS256");
        out.put("status", "active");
        return out;
    }

    public String signingKid() {
        ensureKey();
        return activeKid;
    }

    public long idTokenTtl() {
        return props.getIdTokenTtl();
    }

    public String sign(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKid()).type(JOSEObjectType.JWT).build(),
                    claims);
            jwt.sign(new RSASSASigner(signingKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw ApiException.internal("签发令牌失败");
        }
    }

    public JWTClaimsSet verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            String kid = jwt.getHeader().getKeyID();
            boolean verified = false;
            for (Map<String, Object> row : db.list(
                    "SELECT public_jwk FROM signing_keys WHERE status IN ('active','retired') ORDER BY created_at DESC")) {
                try {
                    JWK jwk = JWK.parse(Json.write(row.get("public_jwk")));
                    if (jwk instanceof RSAKey rsa && (kid == null || kid.equals(rsa.getKeyID()))
                            && jwt.verify(new RSASSAVerifier(rsa))) {
                        verified = true;
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
            if (!verified) {
                throw ApiException.unauthorized("令牌签名无效");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims.getExpirationTime() == null || claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
                throw ApiException.unauthorized("令牌已过期");
            }
            return claims;
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.unauthorized("令牌无效");
        }
    }

    public Map<String, Object> jwks() {
        ensureKey();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keys", db.list("SELECT public_jwk FROM signing_keys WHERE status IN ('active','retired') ORDER BY created_at DESC")
                .stream().map(k -> k.get("public_jwk")).toList());
        return out;
    }

    public JWTClaimsSet claims(String subject, String tenantId, String sessionId, String clientId,
                               String scope, List<String> amr, String acr, long ttlSeconds,
                               String type, Map<String, Object> extra) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(props.getIssuer())
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                .jwtID(Ids.uuidStr())
                .claim("tenant_id", tenantId)
                .claim("sid", sessionId)
                .claim("client_id", clientId)
                .claim("scope", scope == null ? "" : scope)
                .claim("amr", amr == null ? List.of("pwd") : amr)
                .claim("acr", acr == null ? "urn:auth:acr:pwd" : acr)
                .claim("type", type)
                .audience(List.of(clientId == null || clientId.isBlank() ? "auth-center" : clientId));
        if (extra != null) {
            extra.forEach(builder::claim);
        }
        return builder.build();
    }
}
