package com.security.filter;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

@Provider
public class RateLimitFilter implements ContainerRequestFilter {

    static class Entry {
        int count;
        long windowStart;
    }

    private final ConcurrentHashMap<String, Entry> store;
    private String mode = "IP";
    private int limit = 100;
    private int windowSec = 60;

    public RateLimitFilter() {
        this.store = new ConcurrentHashMap<>();
        loadConfig();
    }

    RateLimitFilter(ConcurrentHashMap<String, Entry> store, String mode, int limit, int windowSec) {
        this.store = store;
        this.mode = mode;
        this.limit = limit;
        this.windowSec = windowSec;
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
    public void filter(ContainerRequestContext ctx) {
        String key = getKey(ctx);
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
            ctx.abortWith(
                Response.status(429)
                        .entity("{\"message\":\"Too many requests\"}")
                        .build()
            );
        }
    }

    String getKey(ContainerRequestContext ctx) {
        if ("GLOBAL".equalsIgnoreCase(mode)) return "global";
        String ip = ctx.getHeaderString("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = "unknown";
        }
        return "ip:" + ip;
    }
}
