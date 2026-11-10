package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.AuthContext;
import com.platform.auth.service.SamlService;
import com.platform.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class SamlController {
    private final SamlService saml;

    public SamlController(SamlService saml) {
        this.saml = saml;
    }

    @GetMapping(value = "/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    public String metadata() {
        return saml.metadata();
    }

    @GetMapping(value = "/saml/sso", produces = MediaType.TEXT_HTML_VALUE)
    public String sso(@RequestParam Map<String, String> params, AuthContext ctx) {
        return saml.sso(params, ctx);
    }

    @RequestMapping(value = "/saml/slo", method = {org.springframework.web.bind.annotation.RequestMethod.GET,
            org.springframework.web.bind.annotation.RequestMethod.POST})
    public ResponseEntity<?> slo(@RequestParam Map<String, String> params,
                                 @org.springframework.web.bind.annotation.RequestBody(required = false) String body) {
        Map<String, Object> result = saml.slo(params);
        Object redirect = result.get("redirect_uri");
        if (redirect != null && !String.valueOf(redirect).isBlank()) {
            return ResponseEntity.status(302).location(java.net.URI.create(String.valueOf(redirect))).build();
        }
        return ResponseEntity.ok(Api.ok(result));
    }

    @PostMapping("/api/v1/auth/federated/saml/acs")
    public ResponseEntity<?> acs(@RequestParam Map<String, String> params,
                                 @org.springframework.web.bind.annotation.RequestBody(required = false) String body,
                                 HttpServletRequest request) {
        Map<String, String> form = new java.util.LinkedHashMap<>(params);
        if (body != null && !body.isBlank()) {
            for (String pair : body.split("&")) {
                String[] parts = pair.split("=", 2);
                if (parts.length == 2) {
                    form.put(java.net.URLDecoder.decode(parts[0], java.nio.charset.StandardCharsets.UTF_8),
                            java.net.URLDecoder.decode(parts[1], java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        }
        Map<String, Object> result = saml.acs(form.get("SAMLResponse"), form.get("RelayState"),
                new SessionService.LoginMeta(AuthController.clientIp(request), request.getHeader("User-Agent"),
                        request.getHeader("X-Device-Id"), request.getHeader("X-Device-Name"),
                        request.getHeader("X-Request-Id")));
        Object relay = result.get("relay_state");
        if (relay != null && !String.valueOf(relay).isBlank()) {
            String url = String.valueOf(relay);
            return ResponseEntity.status(302).location(java.net.URI.create(url)).build();
        }
        return ResponseEntity.ok(Api.ok(result));
    }
}
