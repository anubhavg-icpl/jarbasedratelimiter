package com.security.filter;

import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitInterceptor implements HandlerInterceptor {

    static class Entry {
        int count;
        long windowStart;
    }

    private final ConcurrentHashMap<String, Entry> store;
    private int limit;
    private int windowSec;

    public RateLimitInterceptor() {
        this(new ConcurrentHashMap<>(), 100, 60);
    }

    RateLimitInterceptor(ConcurrentHashMap<String, Entry> store, int limit, int windowSec) {
        this.store = store;
        this.limit = limit;
        this.windowSec = windowSec;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String key = "ip:" + request.getRemoteAddr();
        long now = System.currentTimeMillis();

        Entry entry = store.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart > windowSec * 1000L) {
                Entry e = new Entry();
                e.count = 1;
                e.windowStart = now;
                return e;
            }
            existing.count++;
            return existing;
        });

        if (entry.count > limit) {
            response.setStatus(429);
            response.getWriter().write("Too many requests");
            return false;
        }
        return true;
    }
}
