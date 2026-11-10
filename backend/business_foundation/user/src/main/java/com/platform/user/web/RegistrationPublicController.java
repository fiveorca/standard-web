package com.platform.user.web;

import com.platform.user.common.Api;
import com.platform.user.common.Body;
import com.platform.user.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class RegistrationPublicController {
    private final RegistrationService registrations;
    private final RequestContext ctx;

    public RegistrationPublicController(RegistrationService registrations, RequestContext ctx) {
        this.registrations = registrations;
        this.ctx = ctx;
    }

    @PostMapping("/api/v1/registrations")
    public Map<String, Object> register(@RequestBody(required = false) Map<String, Object> body,
                                        HttpServletRequest request) {
        return Api.ok(registrations.register(Body.of(body), ctx.meta(request)));
    }
}
