package com.xxl.job.admin.framework.web.xxlsso;

import com.xxl.sso.core.auth.interceptor.XxlSsoWebInterceptor;
import com.xxl.sso.core.bootstrap.XxlSsoBootstrap;
import com.xxl.sso.core.constant.Const;
import jakarta.annotation.Resource;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import java.net.URI;

/**
 * @author xuxueli 2018-11-15
 */
@Configuration
public class XxlSsoConfig implements WebMvcConfigurer {


    @Value("${xxl-sso.token.key}")
    private String tokenKey;

    @Value("${xxl-sso.token.timeout}")
    private long tokenTimeout;

    @Value("${xxl-sso.client.excluded.paths}")
    private String excludedPaths;

    @Value("${xxl-sso.client.login.path}")
    private String loginPath;


    @Resource
    private SimpleLoginStore loginStore;


    /**
     * 1、配置 XxlSsoBootstrap
     */
    @Bean(initMethod = "start", destroyMethod = "stop")
    public XxlSsoBootstrap xxlSsoBootstrap() {

        XxlSsoBootstrap bootstrap = new XxlSsoBootstrap();
        bootstrap.setLoginStore(loginStore);
        bootstrap.setTokenKey(tokenKey);
        bootstrap.setTokenTimeout(tokenTimeout);
        return bootstrap;
    }

    /**
     * 2、配置 XxlSso 拦截器
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {

        // 2.1、build xxl-sso interceptor
        XxlSsoWebInterceptor webInterceptor = new XxlSsoWebInterceptor(excludedPaths, loginPath);

        // 2.2、add interceptor
        registry.addInterceptor(webInterceptor).addPathPatterns("/**");
    }

    public static boolean isValidCsrfRequest(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod())) {
            return false;
        }
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        if (fetchSite != null) {
            return "same-origin".equals(fetchSite);
        }
        String origin = request.getHeader("Origin");
        if (origin == null) {
            origin = request.getHeader("Referer");
        }
        if (origin == null) {
            return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
        }
        try {
            URI source = URI.create(origin);
            URI target = URI.create(request.getRequestURL().toString());
            int sourcePort = source.getPort() == -1 ? ("https".equalsIgnoreCase(source.getScheme()) ? 443 : 80) : source.getPort();
            int targetPort = target.getPort() == -1 ? ("https".equalsIgnoreCase(target.getScheme()) ? 443 : 80) : target.getPort();
            return source.getHost() != null && source.getUserInfo() == null
                    && target.getScheme().equalsIgnoreCase(source.getScheme())
                    && source.getHost().equalsIgnoreCase(target.getHost()) && sourcePort == targetPort;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Bean
    public Filter sameSiteCookieFilter() {
        return (request, response, chain) -> chain.doFilter(request, new HttpServletResponseWrapper((HttpServletResponse) response) {
            @Override
            public void addCookie(Cookie cookie) {
                if (Const.XXL_SSO_TOKEN.equals(cookie.getName())) {
                    cookie.setAttribute("SameSite", "Lax");
                }
                super.addCookie(cookie);
            }
        });
    }

}
