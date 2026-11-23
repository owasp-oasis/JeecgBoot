package org.jeecg.modules.system.cache;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.zhyd.oauth.cache.AuthCacheConfig;
import me.zhyd.oauth.cache.AuthStateCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.Collections;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


public class AuthStateRedisCache implements AuthStateCache {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    private ValueOperations<String, String> valueOperations;

    @PostConstruct
    public void init() {
        valueOperations = redisTemplate.opsForValue();
    }

    /**
     * 存入缓存，默认3分钟
     *
     * @param key   缓存key
     * @param value 缓存内容
     */
    @Override
    public void cache(String key, String value) {
        valueOperations.set(key, value, AuthCacheConfig.timeout, TimeUnit.MILLISECONDS);
    }

    /**
     * 存入缓存
     *
     * @param key     缓存key
     * @param value   缓存内容
     * @param timeout 指定缓存过期时间（毫秒）
     */
    @Override
    public void cache(String key, String value, long timeout) {
        valueOperations.set(key, value, timeout, TimeUnit.MILLISECONDS);
    }

    /**
     * 获取缓存内容
     *
     * @param key 缓存key
     * @return 缓存内容
     */
    @Override
    public String get(String key) {
        return valueOperations.get(key);
    }

    /**
     * 是否存在key，如果对应key的value值已过期，也返回false
     *
     * @param key 缓存key
     * @return true：存在key，并且value没过期；false：key不存在或者已过期
     */
    @Override
    public boolean containsKey(String key) {
        return redisTemplate.hasKey(key);
    }

    public void cacheBrowserState(String source, String state, HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("thirdLoginState_" + state, UUID.randomUUID().toString());
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setAttribute("SameSite", "Lax");
        cookie.setPath("/");
        cache("thirdLoginState::" + source.toLowerCase(Locale.ROOT) + "::" + state, cookie.getValue());
        response.addCookie(cookie);
    }

    public boolean consumeBrowserState(String source, String state, HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (state == null || state.isEmpty() || cookies == null || response == null) {
            return false;
        }
        Cookie stateCookie = null;
        for (Cookie cookie : cookies) {
            if (("thirdLoginState_" + state).equals(cookie.getName())) {
                if (stateCookie != null) {
                    return false;
                }
                stateCookie = cookie;
            }
        }
        if (stateCookie == null) {
            return false;
        }
        Long consumed = redisTemplate.execute(new DefaultRedisScript<>(
                "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
                Long.class), Collections.singletonList("thirdLoginState::" + source.toLowerCase(Locale.ROOT) + "::" + state), stateCookie.getValue());
        stateCookie.setHttpOnly(true);
        stateCookie.setSecure(request.isSecure());
        stateCookie.setAttribute("SameSite", "Lax");
        stateCookie.setPath("/");
        stateCookie.setMaxAge(0);
        response.addCookie(stateCookie);
        return Long.valueOf(1).equals(consumed);
    }
}
