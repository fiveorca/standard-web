package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.CryptoBox;
import com.platform.auth.security.JwtService;
import com.platform.auth.security.Totp;
import com.platform.auth.security.WebAuthn;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class MfaService {
    private final Db db;
    private final AppProps props;
    private final CryptoBox crypto;
    private final JwtService jwt;
    private final SessionService sessions;
    private final IdentityService identities;
    private final RbacService rbac;
    private final AuditService audit;
    private final Map<String, Challenge> registerChallenges = new ConcurrentHashMap<>();
    private final Map<String, Challenge> verifyChallenges = new ConcurrentHashMap<>();

    public MfaService(Db db, AppProps props, CryptoBox crypto, JwtService jwt, SessionService sessions,
                      IdentityService identities, RbacService rbac, AuditService audit) {
        this.db = db;
        this.props = props;
        this.crypto = crypto;
        this.jwt = jwt;
        this.sessions = sessions;
        this.identities = identities;
        this.rbac = rbac;
        this.audit = audit;
    }

    public Map<String, Object> status(String identityId) {
        List<Map<String, Object>> factors = db.list("""
                SELECT id, kind, name, status, verified_at, last_used_at, created_at
                FROM mfa_factors WHERE identity_id = :id ORDER BY created_at
                """, Db.params("id", identityId));
        long recovery = db.count("SELECT count(*) FROM mfa_recovery_codes WHERE identity_id = :id AND used_at IS NULL",
                Db.params("id", identityId));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("factors", factors);
        out.put("enabled", factors.stream().anyMatch(f -> "active".equals(String.valueOf(f.get("status")))));
        out.put("recovery_codes_remaining", recovery);
        return out;
    }

    public Map<String, Object> totpStart(String identityId, Map<String, Object> body) {
        String name = body.get("name") == null ? "Authenticator" : String.valueOf(body.get("name"));
        String secret = Totp.newSecret();
        String id = Ids.uuidStr();
        db.update("""
                INSERT INTO mfa_factors (id, identity_id, kind, name, status, secret_encrypted)
                VALUES (:id, :identity, 'totp', :name, 'pending', :secret)
                ON CONFLICT (identity_id, kind, name) DO UPDATE
                SET secret_encrypted = EXCLUDED.secret_encrypted, status = 'pending'
                """, Db.params("id", id, "identity", identityId, "name", name,
                "secret", crypto.encrypt(secret)));
        Map<String, Object> factor = db.one("""
                SELECT id, kind, name, status FROM mfa_factors WHERE identity_id = :identity AND kind = 'totp' AND name = :name
                """, Db.params("identity", identityId, "name", name));
        String account = String.valueOf(identities.get(identityId).get("username"));
        Map<String, Object> out = new LinkedHashMap<>(factor);
        out.put("secret", secret);
        out.put("otpauth_uri", Totp.provisioningUri(props.getWebauthnRpName(), account, secret));
        return out;
    }

    public Map<String, Object> totpConfirm(String identityId, String factorId, String code) {
        Map<String, Object> factor = db.list("""
                SELECT * FROM mfa_factors WHERE id = :id AND identity_id = :identity AND kind = 'totp'
                """, Db.params("id", factorId, "identity", identityId)).stream().findFirst()
                .orElseThrow(() -> ApiException.notFound("MFA 因子不存在"));
        String secret = crypto.decrypt(String.valueOf(factor.get("secret_encrypted")));
        long counter = Totp.counter(30);
        if (!Totp.verify(secret, code, counter, 1)) {
            throw ApiException.badRequest("动态口令校验失败");
        }
        db.inTx(() -> {
            db.update("""
                    UPDATE mfa_factors SET status = 'active', verified_at = now(), last_used_step = :step
                    WHERE id = :id
                    """, Db.params("step", counter, "id", factorId));
            db.update("UPDATE identities SET updated_at = now() WHERE id = :id", Db.params("id", identityId));
        });
        List<String> codes = regenerateRecovery(identityId);
        audit.log(String.valueOf(identities.get(identityId).get("tenant_id")), identityId,
                "mfa.totp_enabled", "mfa_factor", factorId, "success", null, null, Map.of());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", true);
        out.put("recovery_codes", codes);
        return out;
    }

    public List<String> regenerateRecovery(String identityId) {
        List<String> codes = new ArrayList<>();
        db.inTx(() -> {
            db.update("DELETE FROM mfa_recovery_codes WHERE identity_id = :id", Db.params("id", identityId));
            for (int i = 0; i < 10; i++) {
                String code = Totp.recoveryCode();
                codes.add(code);
                db.update("""
                        INSERT INTO mfa_recovery_codes (identity_id, code_hash) VALUES (:id, :hash)
                        """, Db.params("id", identityId, "hash", Ids.hmacSha256(props.getEncryptionKey(), identityId + "|" + code)));
            }
        });
        return codes;
    }

    public Map<String, Object> verify(Map<String, Object> body, SessionService.LoginMeta meta) {
        String mfaToken = str(body.get("mfa_token"));
        if (mfaToken == null) {
            throw ApiException.badRequest("缺少 mfa_token");
        }
        Map<String, Object> claims = jwt.verify(mfaToken, "mfa");
        String identityId = str(claims.get("sub"));
        String tenantId = str(claims.get("tenant_id"));
        String amr = "otp";
        String recovery = str(body.get("recovery_code"));
        if (recovery != null) {
            Map<String, Object> row = db.list("""
                    SELECT id FROM mfa_recovery_codes WHERE identity_id = :id AND code_hash = :hash AND used_at IS NULL
                    """, Db.params("id", identityId,
                    "hash", Ids.hmacSha256(props.getEncryptionKey(), identityId + "|" + recovery)))
                    .stream().findFirst().orElseThrow(() -> ApiException.badRequest("恢复码无效"));
            db.update("UPDATE mfa_recovery_codes SET used_at = now() WHERE id = :id", Db.params("id", row.get("id")));
        } else {
            String factorId = str(body.get("factor_id"));
            if (factorId == null) {
                throw ApiException.badRequest("缺少 MFA 因子");
            }
            Map<String, Object> factor = db.list("""
                    SELECT * FROM mfa_factors WHERE id = :id AND identity_id = :identity AND status = 'active'
                    """, Db.params("id", factorId, "identity", identityId)).stream().findFirst()
                    .orElseThrow(() -> ApiException.badRequest("MFA 因子不可用"));
            if ("totp".equals(String.valueOf(factor.get("kind")))) {
                String secret = crypto.decrypt(String.valueOf(factor.get("secret_encrypted")));
                long counter = Totp.counter(30);
                if (!Totp.verify(secret, str(body.get("code")), counter, 1)) {
                    throw ApiException.badRequest("动态口令校验失败");
                }
                Long lastStep = factor.get("last_used_step") == null ? null
                        : ((Number) factor.get("last_used_step")).longValue();
                if (lastStep != null && counter <= lastStep) {
                    throw ApiException.badRequest("动态口令已被使用");
                }
                db.update("UPDATE mfa_factors SET last_used_step = :step, last_used_at = now() WHERE id = :id",
                        Db.params("step", counter, "id", factorId));
            } else {
                verifyWebAuthn(identityId, factor, str(body.get("authenticator_data")),
                        str(body.get("client_data_json")), str(body.get("signature")));
                amr = "webauthn";
            }
        }
        Map<String, Object> identity = identities.get(identityId);
        assertActive(identity);
        Map<String, Object> tokens = sessions.issue(identityId, tenantId, "auth-console",
                "openid profile email offline_access", List.of("pwd", amr), "urn:auth:acr:mfa", meta, null);
        audit.log(tenantId, identityId, "mfa.verified", "identity", identityId, "success",
                meta.ip(), meta.userAgent(), Map.of("amr", amr));
        return tokens;
    }

    public Map<String, Object> webauthnRegisterStart(AuthContext ctx) {
        List<String> existing = db.list("""
                SELECT credential FROM mfa_factors WHERE identity_id = :id AND kind = 'webauthn' AND status = 'active'
                """, Db.params("id", ctx.identityId())).stream()
                .map(r -> String.valueOf(Json.readMap(r.get("credential")).get("credential_id"))).toList();
        String challenge = WebAuthn.randomChallenge();
        registerChallenges.put(ctx.identityId(), new Challenge(challenge, Instant.now().plusSeconds(300)));
        Map<String, Object> identity = identities.get(ctx.identityId());
        return WebAuthn.registrationOptions(props.getWebauthnRpId(), props.getWebauthnRpName(), ctx.identityId(),
                String.valueOf(identity.get("username")), str(identity.get("display_name")), existing);
    }

    public Map<String, Object> webauthnRegisterFinish(AuthContext ctx, Map<String, Object> body) {
        Challenge challenge = registerChallenges.remove(ctx.identityId());
        if (challenge == null || challenge.expiresAt.isBefore(Instant.now())) {
            throw ApiException.badRequest("WebAuthn 注册会话已过期");
        }
        Map<String, Object> credential = WebAuthn.register(str(body.get("attestation_object")),
                str(body.get("client_data_json")), challenge.value, props.getWebauthnOrigin(), props.getWebauthnRpId());
        String name = body.get("name") == null ? "Passkey" : String.valueOf(body.get("name"));
        String id = Ids.uuidStr();
        db.update("""
                INSERT INTO mfa_factors (id, identity_id, kind, name, status, credential, verified_at)
                VALUES (:id, :identity, 'webauthn', :name, 'active', :credential, now())
                ON CONFLICT (identity_id, kind, name) DO UPDATE
                SET credential = EXCLUDED.credential, status = 'active', verified_at = now()
                """, Db.params("id", id, "identity", ctx.identityId(), "name", name,
                "credential", Json.jsonb(credential)));
        audit.log(ctx.tenantId(), ctx.identityId(), "mfa.webauthn_registered", "mfa_factor", id, "success",
                null, null, Map.of("name", name));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id);
        out.put("name", name);
        out.put("kind", "webauthn");
        out.put("status", "active");
        return out;
    }

    public Map<String, Object> webauthnVerifyStart(Map<String, Object> body) {
        String identityId = resolveIdentity(body);
        List<Map<String, Object>> factors = db.list("""
                SELECT * FROM mfa_factors WHERE identity_id = :id AND kind = 'webauthn' AND status = 'active'
                """, Db.params("id", identityId));
        if (factors.isEmpty()) {
            throw ApiException.badRequest("没有可用的 Passkey");
        }
        String challenge = WebAuthn.randomChallenge();
        verifyChallenges.put(identityId, new Challenge(challenge, Instant.now().plusSeconds(300)));
        List<String> ids = factors.stream()
                .map(f -> String.valueOf(Json.readMap(f.get("credential")).get("credential_id"))).toList();
        Map<String, Object> options = WebAuthn.assertionOptions(props.getWebauthnRpId(), challenge, ids);
        options.put("mfa_token", body.get("mfa_token") == null ? null : body.get("mfa_token"));
        return options;
    }

    public Map<String, Object> webauthnVerifyFinish(Map<String, Object> body, SessionService.LoginMeta meta) {
        String identityId = resolveIdentity(body);
        Challenge challenge = verifyChallenges.remove(identityId);
        if (challenge == null || challenge.expiresAt.isBefore(Instant.now())) {
            throw ApiException.badRequest("WebAuthn 验证会话已过期");
        }
        String credentialId = str(body.get("credential_id"));
        Map<String, Object> factor = db.list("""
                SELECT * FROM mfa_factors WHERE identity_id = :id AND kind = 'webauthn' AND status = 'active'
                """, Db.params("id", identityId)).stream()
                .filter(f -> credentialId != null
                        && credentialId.equals(String.valueOf(Json.readMap(f.get("credential")).get("credential_id"))))
                .findFirst().orElseThrow(() -> ApiException.badRequest("凭据不存在"));
        verifyWebAuthn(identityId, factor, str(body.get("authenticator_data")),
                str(body.get("client_data_json")), str(body.get("signature")), challenge.value);
        Map<String, Object> identity = identities.get(identityId);
        assertActive(identity);
        Map<String, Object> tokens = sessions.issue(identityId, String.valueOf(identity.get("tenant_id")),
                "auth-console", "openid profile email offline_access", List.of("pwd", "webauthn"),
                "urn:auth:acr:mfa", meta, null);
        audit.log(String.valueOf(identity.get("tenant_id")), identityId, "mfa.webauthn_verified", "identity", identityId,
                "success", meta.ip(), meta.userAgent(), Map.of());
        return tokens;
    }

    private void verifyWebAuthn(String identityId, Map<String, Object> factor, String authenticatorData,
                                String clientDataJson, String signature) {
        verifyWebAuthn(identityId, factor, authenticatorData, clientDataJson, signature, null);
    }

    private void verifyWebAuthn(String identityId, Map<String, Object> factor, String authenticatorData,
                                String clientDataJson, String signature, String expectedChallenge) {
        if (expectedChallenge == null) {
            Challenge challenge = verifyChallenges.remove(identityId);
            if (challenge != null) {
                expectedChallenge = challenge.value;
            }
        }
        String challengeValue = expectedChallenge != null ? expectedChallenge
                : str(Json.readMap(clientDataJson).get("challenge"));
        Map<String, Object> credential = Json.readMap(factor.get("credential"));
        long signCount = WebAuthn.verifyAssertion(credential, authenticatorData, clientDataJson, signature,
                challengeValue, props.getWebauthnOrigin(), props.getWebauthnRpId());
        credential.put("sign_count", signCount);
        db.update("UPDATE mfa_factors SET credential = :credential, sign_count = :count, last_used_at = now() WHERE id = :id",
                Db.params("credential", Json.jsonb(credential), "count", signCount, "id", factor.get("id")));
    }

    public void deleteFactor(AuthContext ctx, String factorId) {
        int updated = db.update("DELETE FROM mfa_factors WHERE id = :id AND identity_id = :identity",
                Db.params("id", factorId, "identity", ctx.identityId()));
        if (updated == 0) {
            throw ApiException.notFound("MFA 因子不存在");
        }
        audit.log(ctx.tenantId(), ctx.identityId(), "mfa.factor_removed", "mfa_factor", factorId, "success",
                null, null, Map.of());
    }

    public void adminReset(String identityId) {
        db.inTx(() -> {
            db.update("DELETE FROM mfa_factors WHERE identity_id = :id", Db.params("id", identityId));
            db.update("DELETE FROM mfa_recovery_codes WHERE identity_id = :id", Db.params("id", identityId));
        });
    }

    private String resolveIdentity(Map<String, Object> body) {
        String mfaToken = str(body.get("mfa_token"));
        if (mfaToken == null) {
            throw ApiException.badRequest("缺少 mfa_token");
        }
        String identityId = str(jwt.verify(mfaToken, "mfa").get("sub"));
        if (identities.get(identityId) == null) {
            throw ApiException.unauthorized("身份不存在");
        }
        return identityId;
    }

    private void assertActive(Map<String, Object> identity) {
        if (!"active".equals(String.valueOf(identity.get("status")))) {
            throw ApiException.forbidden("账户当前不可用");
        }
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private record Challenge(String value, Instant expiresAt) {}
}
