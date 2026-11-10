package com.platform.user.config;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.AuthContext;
import com.platform.user.common.CurrentUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class AuthContextResolver implements HandlerMethodArgumentResolver {
    private final AuthClient auth;

    public AuthContextResolver(AuthClient auth) {
        this.auth = auth;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return AuthContext.class.equals(parameter.getParameterType())
                || parameter.hasParameterAnnotation(CurrentUser.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        return authenticate(request);
    }

    public AuthContext authenticate(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            throw com.platform.user.common.ApiException.unauthorized("缺少访问令牌");
        }
        String token;
        if (header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = header.substring(7).trim();
        } else {
            throw com.platform.user.common.ApiException.unauthorized("访问令牌格式应为 Bearer");
        }
        if (token.isEmpty()) {
            throw com.platform.user.common.ApiException.unauthorized("缺少访问令牌");
        }
        return auth.verifyAccessToken(token);
    }
}
