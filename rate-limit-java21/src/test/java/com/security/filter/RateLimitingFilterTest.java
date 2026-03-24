package com.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitingFilterTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain chain;
    private StringWriter responseBody;

    @BeforeEach
    void setUp() throws Exception {
        responseBody = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void allowsRequestsWithinLimit() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");

        for (int i = 0; i < 5; i++) {
            filter.doFilter(request, response, chain);
        }
        verify(chain, times(5)).doFilter(request, response);
    }

    @Test
    void blocksRequestsOverLimit() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 3, 60);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        for (int i = 0; i < 3; i++) {
            filter.doFilter(request, response, chain);
        }
        filter.doFilter(request, response, chain);

        verify(chain, times(3)).doFilter(request, response);
        verify(response, atLeastOnce()).setStatus(429);
    }

    @Test
    void globalModeSharesCounter() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "GLOBAL", 2, 60);

        HttpServletRequest req1 = mock(HttpServletRequest.class);
        HttpServletRequest req2 = mock(HttpServletRequest.class);

        filter.doFilter(req1, response, chain);
        filter.doFilter(req2, response, chain);
        filter.doFilter(req1, response, chain);

        verify(chain, times(2)).doFilter(any(), eq(response));
        verify(response, atLeastOnce()).setStatus(429);
    }

    @Test
    void windowResetsAfterExpiry() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 2, 1);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);
        verify(chain, times(2)).doFilter(request, response);

        Thread.sleep(1100);
        FilterChain chain2 = mock(FilterChain.class);
        filter.doFilter(request, response, chain2);
        verify(chain2, times(1)).doFilter(request, response);
    }

    @Test
    void xForwardedForHeader() {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.50");

        assertEquals("ip:203.0.113.50", filter.getKey(request));
    }

    @Test
    void fallbackToRemoteAddr() {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");

        assertEquals("ip:192.168.1.100", filter.getKey(request));
    }

    @Test
    void retryAfterHeader() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 1, 60);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);

        verify(response).setHeader(eq("Retry-After"), anyString());
    }

    @Test
    void differentIPsHaveSeparateLimits() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitingFilter.Entry>();
        var filter = new RateLimitingFilter(store, "IP", 1, 60);

        HttpServletRequest req1 = mock(HttpServletRequest.class);
        when(req1.getRemoteAddr()).thenReturn("10.0.0.1");
        HttpServletResponse resp1 = mock(HttpServletResponse.class);

        HttpServletRequest req2 = mock(HttpServletRequest.class);
        when(req2.getRemoteAddr()).thenReturn("10.0.0.2");
        HttpServletResponse resp2 = mock(HttpServletResponse.class);

        filter.doFilter(req1, resp1, chain);
        filter.doFilter(req2, resp2, chain);

        verify(chain).doFilter(req1, resp1);
        verify(chain).doFilter(req2, resp2);
    }
}
