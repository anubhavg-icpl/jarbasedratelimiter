package com.security.filter;

import org.junit.Before;
import org.junit.Test;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class RateLimitFilterTest {

    private ContainerRequestContext ctx;

    @Before
    public void setUp() {
        ctx = mock(ContainerRequestContext.class);
    }

    @Test
    public void testAllowsWithinLimit() {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        for (int i = 0; i < 5; i++) {
            filter.filter(ctx);
        }
        verify(ctx, never()).abortWith(any(Response.class));
    }

    @Test
    public void testBlocksOverLimit() {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "IP", 2, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        filter.filter(ctx);
        filter.filter(ctx);
        filter.filter(ctx);

        verify(ctx).abortWith(argThat(resp -> resp.getStatus() == 429));
    }

    @Test
    public void testGlobalMode() {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "GLOBAL", 2, 60);

        ContainerRequestContext ctx1 = mock(ContainerRequestContext.class);
        when(ctx1.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");
        ContainerRequestContext ctx2 = mock(ContainerRequestContext.class);
        when(ctx2.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.2");

        filter.filter(ctx1);
        filter.filter(ctx2);
        filter.filter(ctx1); // 3rd should be blocked

        verify(ctx1).abortWith(argThat(resp -> resp.getStatus() == 429));
    }

    @Test
    public void testKeyWithXForwardedFor() {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("203.0.113.50");

        assertEquals("ip:203.0.113.50", filter.getKey(ctx));
    }

    @Test
    public void testKeyWithoutXForwardedFor() {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn(null);

        assertEquals("ip:unknown", filter.getKey(ctx));
    }

    @Test
    public void testWindowReset() throws Exception {
        ConcurrentHashMap<String, RateLimitFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitFilter filter = new RateLimitFilter(store, "IP", 1, 1);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        filter.filter(ctx);
        filter.filter(ctx); // blocked
        verify(ctx).abortWith(argThat(resp -> resp.getStatus() == 429));

        Thread.sleep(1100);
        ContainerRequestContext ctx2 = mock(ContainerRequestContext.class);
        when(ctx2.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");
        filter.filter(ctx2);
        verify(ctx2, never()).abortWith(any(Response.class));
    }
}
