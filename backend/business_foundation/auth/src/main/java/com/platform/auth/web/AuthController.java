package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Cookies;
import com.platform.auth.config.AppProps;
import com.platform.auth.service.FederationService;
import com.platform.auth.service.IdentityService;
import com.platform.auth.service.MfaService;
import com.platform.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final IdentityService identities;
    private final SessionService sessions;
    private final MfaService mfa;
    private final FederationService federation;
    private final AppProps props;

    public AuthController(IdentityService identities, SessionService sessions, MfaService mfa,
                          FederationService federation, AppProps props) {
        this.identities = identities;
        this.sessions = sessions;
        this.mfa = mfa;
        this.federation = federation;
        this.props = props;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> body,
                                                        HttpServletRequest request) {
        return Api.created(identities.register(body, meta(request)));
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, Object> body,
                                     HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> result = identities.login(body, meta(request));
        writeCookies(result, response);
        return Api.ok(result);
    }

    @PostMapping("/login/otp")
    public Map<String, Object> loginOtp(@RequestBody Map<String, Object> body,
                                        HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> result = identities.loginOtp(body, meta(request));
        writeCookies(result, response);
        return Api.ok(result);
    }

    @PostMapping("/login/otp/request")
    public Map<String, Object> requestOtp(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return Api.ok(identities.requestOtp(body, meta(request)));
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(@RequestBody(required = false) Map<String, Object> body,
                                      AuthContext ctx, HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> payload = body == null ? Map.of() : body;
        sessions.logout(ctx, Boolean.TRUE.equals(payload.get("all_devices")),
                payload.get("device_id") == null ? null : String.valueOf(payload.get("device_id")));
        clearCookies(response);
        return Api.ok(Map.of("logged_out", true));
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody(required = false) Map<String, Object> body,
                                       HttpServletRequest request, HttpServletResponse response) {
        String token = body != null && body.get("refresh_token") != null
                ? String.valueOf(body.get("refresh_token")) : Cookies.read(request, "refresh_token");
        if (token == null) {
            throw ApiException.unauthorized("缺少刷新令牌");
        }
        Map<String, Object> result = sessions.refresh(token, null, meta(request));
        writeCookies(result, response);
        return Api.ok(result);
    }

    @GetMapping("/me")
    public Map<String, Object> me(AuthContext ctx) {
        return Api.ok(identities.me(ctx.identityId()));
    }

    @PatchMapping("/me")
    public Map<String, Object> updateMe(@RequestBody Map<String, Object> body, AuthContext ctx) {
        return Api.ok(identities.updateSelf(ctx.identityId(), body));
    }

    @PostMapping("/password/change")
    public Map<String, Object> changePassword(@RequestBody Map<String, Object> body,
                                              AuthContext ctx, HttpServletRequest request,
                                              HttpServletResponse response) {
        Map<String, Object> result = identities.changePassword(ctx.identityId(), body, meta(request));
        clearCookies(response);
        return Api.ok(result);
    }

    @PostMapping("/password/forgot")
    public Map<String, Object> forgotPassword(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return Api.ok(identities.forgotPassword(body, meta(request)));
    }

    @PostMapping("/password/reset")
    public Map<String, Object> resetPassword(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return Api.ok(identities.resetPassword(body, meta(request)));
    }

    @PostMapping("/email/verify")
    public Map<String, Object> verifyEmail(@RequestBody Map<String, Object> body, AuthContext ctx,
                                           HttpServletRequest request) {
        return Api.ok(identities.confirmVerification(ctx.identityId(), "email",
                String.valueOf(body.get("code")), meta(request)));
    }

    @PostMapping("/email/verify/request")
    public Map<String, Object> requestEmailVerify(AuthContext ctx, HttpServletRequest request) {
        return Api.ok(identities.requestVerification(ctx.identityId(), "email", meta(request)));
    }

    @PostMapping("/phone/verify")
    public Map<String, Object> verifyPhone(@RequestBody Map<String, Object> body, AuthContext ctx,
                                           HttpServletRequest request) {
        return Api.ok(identities.confirmVerification(ctx.identityId(), "phone",
                String.valueOf(body.get("code")), meta(request)));
    }

    @PostMapping("/phone/verify/request")
    public Map<String, Object> requestPhoneVerify(AuthContext ctx, HttpServletRequest request) {
        return Api.ok(identities.requestVerification(ctx.identityId(), "phone", meta(request)));
    }

    @PostMapping("/contact/change")
    public Map<String, Object> confirmContact(@RequestBody Map<String, Object> body, AuthContext ctx,
                                              HttpServletRequest request) {
        return Api.ok(identities.confirmContactChange(ctx.identityId(), body, meta(request)));
    }

    @PostMapping("/contact/change/request")
    public Map<String, Object> requestContact(@RequestBody Map<String, Object> body, AuthContext ctx,
                                              HttpServletRequest request) {
        return Api.ok(identities.requestContactChange(ctx.identityId(), body, meta(request)));
    }

    @GetMapping("/login-history")
    public Map<String, Object> loginHistory(AuthContext ctx) {
        return Api.ok(Map.of("items", sessions.history(ctx.identityId())));
    }

    @GetMapping("/login-anomalies")
    public Map<String, Object> loginAnomalies(AuthContext ctx) {
        return Api.ok(Map.of("items", sessions.anomalies(ctx.identityId())));
    }

    @GetMapping("/consents")
    public Map<String, Object> consents(AuthContext ctx) {
        return Api.ok(Map.of("items", identities.consents(ctx.identityId())));
    }

    @DeleteMapping("/consents/{clientId}")
    public Map<String, Object> revokeConsent(@PathVariable String clientId, AuthContext ctx) {
        identities.revokeConsent(ctx.identityId(), clientId);
        return Api.ok(Map.of("revoked", true));
    }

    @GetMapping("/sessions")
    public Map<String, Object> sessions(AuthContext ctx) {
        return Api.ok(Map.of("items", sessions.list(ctx.identityId())));
    }

    @DeleteMapping("/sessions/{id}")
    public Map<String, Object> revokeSession(@PathVariable String id, AuthContext ctx) {
        sessions.revokeSession(ctx.identityId(), id);
        return Api.ok(Map.of("revoked", true));
    }

    @PutMapping("/sessions/{id}/device")
    public Map<String, Object> renameDevice(@PathVariable String id, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        sessions.renameDevice(ctx.identityId(), id, body.get("device_name") == null
                ? null : String.valueOf(body.get("device_name")));
        return Api.ok(Map.of("updated", true));
    }

    @DeleteMapping("/sessions/devices/{deviceId}")
    public Map<String, Object> revokeDevice(@PathVariable String deviceId, AuthContext ctx) {
        sessions.revokeDevice(ctx.identityId(), deviceId);
        return Api.ok(Map.of("revoked", true));
    }

    @GetMapping("/mfa")
    public Map<String, Object> mfaStatus(AuthContext ctx) {
        return Api.ok(mfa.status(ctx.identityId()));
    }

    @DeleteMapping("/mfa/factors/{id}")
    public Map<String, Object> deleteFactor(@PathVariable String id, AuthContext ctx) {
        mfa.deleteFactor(ctx, id);
        return Api.ok(Map.of("deleted", true));
    }

    @PostMapping("/mfa/recovery-codes")
    public Map<String, Object> recoveryCodes(AuthContext ctx) {
        return Api.ok(Map.of("recovery_codes", mfa.regenerateRecovery(ctx.identityId())));
    }

    @PostMapping("/mfa/totp/start")
    public Map<String, Object> totpStart(@RequestBody(required = false) Map<String, Object> body, AuthContext ctx) {
        return Api.ok(mfa.totpStart(ctx.identityId(), body == null ? Map.of() : body));
    }

    @PostMapping("/mfa/totp/confirm")
    public Map<String, Object> totpConfirm(@RequestBody Map<String, Object> body, AuthContext ctx) {
        return Api.ok(mfa.totpConfirm(ctx.identityId(), String.valueOf(body.get("factor_id")),
                String.valueOf(body.get("code"))));
    }

    @PostMapping("/mfa/verify")
    public Map<String, Object> verifyMfa(@RequestBody Map<String, Object> body, HttpServletRequest request,
                                         HttpServletResponse response) {
        Map<String, Object> result = mfa.verify(body, meta(request));
        writeCookies(result, response);
        return Api.ok(result);
    }

    @PostMapping("/mfa/webauthn/register/start")
    public Map<String, Object> webauthnRegisterStart(AuthContext ctx) {
        return Api.ok(mfa.webauthnRegisterStart(ctx));
    }

    @PostMapping("/mfa/webauthn/register/finish")
    public Map<String, Object> webauthnRegisterFinish(@RequestBody Map<String, Object> body, AuthContext ctx) {
        return Api.ok(mfa.webauthnRegisterFinish(ctx, body));
    }

    @PostMapping("/mfa/webauthn/verify/start")
    public Map<String, Object> webauthnVerifyStart(@RequestBody Map<String, Object> body) {
        return Api.ok(mfa.webauthnVerifyStart(body));
    }

    @PostMapping("/mfa/webauthn/verify/finish")
    public Map<String, Object> webauthnVerifyFinish(@RequestBody Map<String, Object> body, HttpServletRequest request,
                                                    HttpServletResponse response) {
        Map<String, Object> result = mfa.webauthnVerifyFinish(body, meta(request));
        writeCookies(result, response);
        return Api.ok(result);
    }

    @GetMapping("/federated/links")
    public Map<String, Object> links(AuthContext ctx) {
        return Api.ok(Map.of("items", federation.links(ctx.identityId())));
    }

    @DeleteMapping("/federated/links/{provider}")
    public Map<String, Object> unlink(@PathVariable String provider, AuthContext ctx) {
        federation.unlink(ctx.identityId(), provider);
        return Api.ok(Map.of("unlinked", true));
    }

    @GetMapping("/federated/{provider}/start")
    public Map<String, Object> federatedStart(@PathVariable String provider,
                                              @RequestParam(required = false) String redirect_uri,
                                              @RequestParam(required = false) String final_redirect) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (redirect_uri != null) {
            body.put("redirect_uri", redirect_uri);
        }
        if (final_redirect != null) {
            body.put("final_redirect", final_redirect);
        }
        return Api.ok(federation.start(provider, body));
    }

    @GetMapping("/federated/{provider}/callback")
    public ResponseEntity<?> federatedCallbackGet(@PathVariable String provider,
                                                  @RequestParam(required = false) String code,
                                                  @RequestParam(required = false) String state,
                                                  HttpServletRequest request, HttpServletResponse response) {
        return completeFederation(provider, code, state, request, response);
    }

    @PostMapping("/federated/{provider}/callback")
    public ResponseEntity<?> federatedCallbackPost(@PathVariable String provider,
                                                   @RequestBody(required = false) Map<String, Object> body,
                                                   @RequestParam(required = false) String code,
                                                   @RequestParam(required = false) String state,
                                                   HttpServletRequest request, HttpServletResponse response) {
        String finalCode = code != null ? code : body == null ? null : String.valueOf(body.get("code"));
        String finalState = state != null ? state : body == null ? null : String.valueOf(body.get("state"));
        return completeFederation(provider, finalCode, finalState, request, response);
    }

    private ResponseEntity<?> completeFederation(String provider, String code, String state,
                                                 HttpServletRequest request, HttpServletResponse response) {
        if (code == null || state == null) {
            throw ApiException.badRequest("缺少 code 或 state");
        }
        Map<String, Object> result = federation.callback(provider, code, state, meta(request));
        writeCookies(result, response);
        Object redirect = result.get("final_redirect");
        if (redirect != null && !String.valueOf(redirect).isBlank()) {
            StringBuilder url = new StringBuilder(String.valueOf(redirect));
            url.append(redirect.toString().contains("?") ? "&" : "?");
            url.append("access_token=").append(result.get("access_token"));
            if (result.get("refresh_token") != null) {
                url.append("&refresh_token=").append(result.get("refresh_token"));
            }
            if (result.get("id_token") != null) {
                url.append("&id_token=").append(result.get("id_token"));
            }
            url.append("&token_type=Bearer&expires_in=").append(result.get("expires_in"));
            return ResponseEntity.status(302).location(URI.create(url.toString())).build();
        }
        return ResponseEntity.ok(Api.ok(result));
    }

    private void writeCookies(Map<String, Object> result, HttpServletResponse response) {
        if (result.get("access_token") != null) {
            Cookies.write(response, "access_token", String.valueOf(result.get("access_token")),
                    props.getAccessTokenTtl(), props.isCookieSecure(), props.getCookieDomain());
        }
        if (result.get("refresh_token") != null) {
            Cookies.write(response, "refresh_token", String.valueOf(result.get("refresh_token")),
                    props.getRefreshTokenTtl(), props.isCookieSecure(), props.getCookieDomain());
        }
        if (result.get("id_token") != null) {
            Cookies.write(response, "id_token", String.valueOf(result.get("id_token")),
                    props.getIdTokenTtl(), props.isCookieSecure(), props.getCookieDomain());
        }
    }

    private void clearCookies(HttpServletResponse response) {
        List.of("access_token", "refresh_token", "id_token").forEach(name ->
                Cookies.clear(response, name, props.isCookieSecure(), props.getCookieDomain()));
    }

    private SessionService.LoginMeta meta(HttpServletRequest request) {
        return new SessionService.LoginMeta(clientIp(request), request.getHeader("User-Agent"),
                request.getHeader("X-Device-Id"), request.getHeader("X-Device-Name"),
                request.getHeader("X-Request-Id"));
    }

    static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
