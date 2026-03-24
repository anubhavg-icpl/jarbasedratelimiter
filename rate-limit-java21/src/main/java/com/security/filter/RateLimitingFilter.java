package com.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitingFilter implements Filter {

    static class Entry {
        int count;
        long windowStart;
    }

    private final ConcurrentHashMap<String, Entry> store;
    private String mode = "IP";
    private int limit = 100;
    private int windowSec = 60;

    public RateLimitingFilter() {
        this.store = new ConcurrentHashMap<>();
    }

    RateLimitingFilter(ConcurrentHashMap<String, Entry> store, String mode, int limit, int windowSec) {
        this.store = store;
        this.mode = mode;
        this.limit = limit;
        this.windowSec = windowSec;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        loadConfig();
    }

    private void loadConfig() {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("rate-limit.properties")) {
            if (is != null) {
                Properties prop = new Properties();
                prop.load(is);
                mode = prop.getProperty("rate.limit.mode", "IP");
                limit = Integer.parseInt(prop.getProperty("rate.limit.permit", "100"));
                windowSec = Integer.parseInt(prop.getProperty("rate.limit.windowSeconds", "60"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String key = getKey(request);
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
            response.setContentType("application/json");
            response.getWriter().write("{\"message\":\"Too many requests\"}");
            long retryAfter = (entry.windowStart + (windowSec * 1000L) - now) / 1000;
            response.setHeader("Retry-After", String.valueOf(Math.max(retryAfter, 0)));
            return;
        }

        chain.doFilter(req, res);
    }

    String getKey(HttpServletRequest request) {
        if ("GLOBAL".equalsIgnoreCase(mode)) {
            return "global";
        }
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return "ip:" + ip;
    }

    @Override
    public void destroy() {}
}
