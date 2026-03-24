package com.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock private ContainerRequestContext ctx;

    @Test
    void allowsWithinLimit() {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        for (int i = 0; i < 5; i++) {
            filter.filter(ctx);
        }
        verify(ctx, never()).abortWith(any(Response.class));
    }

    @Test
    void blocksOverLimit() {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "IP", 2, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        filter.filter(ctx);
        filter.filter(ctx);
        filter.filter(ctx);

        verify(ctx).abortWith(argThat(resp -> resp.getStatus() == 429));
    }

    @Test
    void globalMode() {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "GLOBAL", 2, 60);

        ContainerRequestContext ctx1 = mock(ContainerRequestContext.class);
        ContainerRequestContext ctx2 = mock(ContainerRequestContext.class);

        filter.filter(ctx1);
        filter.filter(ctx2);
        filter.filter(ctx1);

        verify(ctx1).abortWith(argThat(resp -> resp.getStatus() == 429));
    }

    @Test
    void keyWithXForwardedFor() {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("203.0.113.50");

        assertEquals("ip:203.0.113.50", filter.getKey(ctx));
    }

    @Test
    void keyWithoutXForwardedFor() {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "IP", 5, 60);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn(null);

        assertEquals("ip:unknown", filter.getKey(ctx));
    }

    @Test
    void windowReset() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitFilter.Entry>();
        var filter = new RateLimitFilter(store, "IP", 1, 1);
        when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");

        filter.filter(ctx);
        filter.filter(ctx);
        verify(ctx).abortWith(argThat(resp -> resp.getStatus() == 429));

        Thread.sleep(1100);
        ContainerRequestContext ctx2 = mock(ContainerRequestContext.class);
        when(ctx2.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");
        filter.filter(ctx2);
        verify(ctx2, never()).abortWith(any(Response.class));
    }
}
