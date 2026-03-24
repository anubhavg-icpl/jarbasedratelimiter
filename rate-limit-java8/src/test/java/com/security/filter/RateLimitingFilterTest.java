package com.security.filter;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class RateLimitingFilterTest {

    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private StringWriter responseBody;

    @Before
    public void setUp() throws Exception {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        responseBody = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    public void testAllowsRequestsWithinLimit() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");

        for (int i = 0; i < 5; i++) {
            filter.doFilter(request, response, chain);
        }
        verify(chain, times(5)).doFilter(request, response);
    }

    @Test
    public void testBlocksRequestsOverLimit() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 3, 60);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        for (int i = 0; i < 3; i++) {
            filter.doFilter(request, response, chain);
        }
        // 4th request should be blocked
        filter.doFilter(request, response, chain);

        verify(chain, times(3)).doFilter(request, response);
        verify(response, atLeastOnce()).setStatus(429);
    }

    @Test
    public void testGlobalModeSharesCounter() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "GLOBAL", 2, 60);

        HttpServletRequest req1 = mock(HttpServletRequest.class);
        when(req1.getRemoteAddr()).thenReturn("10.0.0.1");
        HttpServletRequest req2 = mock(HttpServletRequest.class);
        when(req2.getRemoteAddr()).thenReturn("10.0.0.2");

        filter.doFilter(req1, response, chain);
        filter.doFilter(req2, response, chain);
        // 3rd request from any IP should be blocked
        filter.doFilter(req1, response, chain);

        verify(chain, times(2)).doFilter(any(), eq(response));
        verify(response, atLeastOnce()).setStatus(429);
    }

    @Test
    public void testWindowResetsAfterExpiry() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 2, 1); // 1 second window
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);
        // 3rd should be blocked
        filter.doFilter(request, response, chain);
        verify(chain, times(2)).doFilter(request, response);

        // Wait for window to expire
        Thread.sleep(1100);
        FilterChain chain2 = mock(FilterChain.class);
        filter.doFilter(request, response, chain2);
        verify(chain2, times(1)).doFilter(request, response);
    }

    @Test
    public void testXForwardedForHeader() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.50");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        String key = filter.getKey(request);
        assertEquals("ip:203.0.113.50", key);
    }

    @Test
    public void testFallbackToRemoteAddr() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 5, 60);
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");

        String key = filter.getKey(request);
        assertEquals("ip:192.168.1.100", key);
    }

    @Test
    public void testRetryAfterHeader() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 1, 60);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        filter.doFilter(request, response, chain);
        // 2nd request blocked
        filter.doFilter(request, response, chain);

        verify(response).setHeader(eq("Retry-After"), anyString());
    }

    @Test
    public void testDifferentIPsHaveSeparateLimits() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 1, 60);

        HttpServletRequest req1 = mock(HttpServletRequest.class);
        when(req1.getRemoteAddr()).thenReturn("10.0.0.1");
        HttpServletResponse resp1 = mock(HttpServletResponse.class);
        when(resp1.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        HttpServletRequest req2 = mock(HttpServletRequest.class);
        when(req2.getRemoteAddr()).thenReturn("10.0.0.2");
        HttpServletResponse resp2 = mock(HttpServletResponse.class);
        when(resp2.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        filter.doFilter(req1, resp1, chain);
        filter.doFilter(req2, resp2, chain);

        // Both first requests should pass
        verify(chain).doFilter(req1, resp1);
        verify(chain).doFilter(req2, resp2);
    }
}
