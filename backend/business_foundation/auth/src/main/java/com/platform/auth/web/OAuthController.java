package com.platform.auth.web;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Cookies;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.service.OAuthService;
import com.platform.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth2")
public class OAuthController {
    private final OAuthService oauth;
    private final AppProps props;

    public OAuthController(OAuthService oauth, AppProps props) {
        this.oauth = oauth;
        this.props = props;
    }

    @GetMapping("/authorize")
    public ResponseEntity<?> authorize(@RequestParam Map<String, String> params, AuthContext ctx) {
        Map<String, Object> result = oauth.authorize(ctx, params);
        if (Boolean.TRUE.equals(result.get("consent_required"))) {
            return ResponseEntity.ok(com.platform.auth.common.Api.ok(result));
        }
        return redirect(result);
    }

    @PostMapping("/authorize/consent")
    public ResponseEntity<?> consent(@RequestBody Map<String, Object> body, AuthContext ctx) {
        Map<String, Object> result = oauth.consent(ctx, body);
        if (result.get("error") != null) {
            return ResponseEntity.ok(com.platform.auth.common.Api.ok(result));
        }
        return redirect(result);
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(HttpServletRequest request,
                                                     @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        try {
            Map<String, String> form = new LinkedHashMap<>();
            request.getParameterMap().forEach((key, values) -> {
                if (values.length > 0) {
                    form.put(key, values[0]);
                }
            });
            if (authorization != null && authorization.startsWith("Basic ")) {
                String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
                int index = decoded.indexOf(':');
                if (index > 0) {
                    form.put("client_id", decoded.substring(0, index));
                    form.put("client_secret", decoded.substring(index + 1));
                }
            }
            return ResponseEntity.ok(oauth.token(form, meta(request)));
        } catch (ApiException e) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", e.code());
            error.put("error_description", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return oauth.jwks();
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwksWellKnown() {
        return oauth.jwks();
    }

    @GetMapping("/userinfo")
    public Map<String, Object> userinfo(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                        HttpServletRequest request) {
        String token = bearer(authorization);
        if (token == null) {
            token = Cookies.read(request, "access_token");
        }
        if (token == null) {
            throw ApiException.unauthorized("缺少访问令牌");
        }
        return oauth.userinfo(token);
    }

    @PostMapping("/introspect")
    public Map<String, Object> introspect(@RequestBody(required = false) Map<String, Object> body,
                                          HttpServletRequest request) {
        String token = body != null && body.get("token") != null
                ? String.valueOf(body.get("token")) : request.getParameter("token");
        if (token == null) {
            throw ApiException.badRequest("缺少 token");
        }
        return oauth.introspect(token);
    }

    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        String token = body != null && body.get("token") != null
                ? String.valueOf(body.get("token")) : request.getParameter("token");
        if (token == null) {
            throw ApiException.badRequest("缺少 token");
        }
        oauth.revoke(token, body == null ? null
                : body.get("client_id") == null ? null : String.valueOf(body.get("client_id")));
        return Map.of();
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logoutGet(@RequestParam Map<String, String> params,
                                       HttpServletResponse response) {
        Map<String, Object> result = oauth.endSession(params);
        Cookies.clear(response, "access_token", props.isCookieSecure(), props.getCookieDomain());
        Cookies.clear(response, "refresh_token", props.isCookieSecure(), props.getCookieDomain());
        Cookies.clear(response, "id_token", props.isCookieSecure(), props.getCookieDomain());
        if (result.get("redirect_uri") != null) {
            String url = String.valueOf(result.get("redirect_uri"));
            if (result.get("state") != null) {
                url += (url.contains("?") ? "&" : "?") + "state=" + encode(String.valueOf(result.get("state")));
            }
            return ResponseEntity.status(302).location(URI.create(url)).build();
        }
        return ResponseEntity.ok(com.platform.auth.common.Api.ok(result));
    }

    @PostMapping("/logout")
    public Map<String, Object> logoutPost(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, String> params = new LinkedHashMap<>();
        if (body != null) {
            body.forEach((k, v) -> params.put(k, v == null ? null : String.valueOf(v)));
        }
        return com.platform.auth.common.Api.ok(oauth.endSession(params));
    }

    private ResponseEntity<?> redirect(Map<String, Object> result) {
        String redirectUri = String.valueOf(result.get("redirect_uri"));
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("code=").append(encode(String.valueOf(result.get("code"))));
        if (result.get("state") != null) {
            url.append("&state=").append(encode(String.valueOf(result.get("state"))));
        }
        return ResponseEntity.status(302).location(URI.create(url.toString())).build();
    }

    @GetMapping({"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"})
    public Map<String, Object> discovery() {
        return oauth.discovery();
    }

    private static String bearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        return authorization.substring(7);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private SessionService.LoginMeta meta(HttpServletRequest request) {
        return new SessionService.LoginMeta(AuthController.clientIp(request), request.getHeader("User-Agent"),
                request.getHeader("X-Device-Id"), request.getHeader("X-Device-Name"),
                request.getHeader("X-Request-Id"));
    }
}
