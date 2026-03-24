package com.security.filter;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class RateLimitInterceptorTest {

    private HttpServletRequest request;
    private HttpServletResponse response;
    private StringWriter responseBody;

    @Before
    public void setUp() throws Exception {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
    }

    @Test
    public void testAllowsWithinLimit() throws Exception {
        ConcurrentHashMap<String, RateLimitInterceptor.Entry> store = new ConcurrentHashMap<>();
        RateLimitInterceptor interceptor = new RateLimitInterceptor(store, 5, 60);

        for (int i = 0; i < 5; i++) {
            assertTrue(interceptor.preHandle(request, response, new Object()));
        }
    }

    @Test
    public void testBlocksOverLimit() throws Exception {
        ConcurrentHashMap<String, RateLimitInterceptor.Entry> store = new ConcurrentHashMap<>();
        RateLimitInterceptor interceptor = new RateLimitInterceptor(store, 2, 60);

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertFalse(interceptor.preHandle(request, response, new Object()));
        verify(response).setStatus(429);
    }

    @Test
    public void testWindowReset() throws Exception {
        ConcurrentHashMap<String, RateLimitInterceptor.Entry> store = new ConcurrentHashMap<>();
        RateLimitInterceptor interceptor = new RateLimitInterceptor(store, 1, 1);

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertFalse(interceptor.preHandle(request, response, new Object()));

        Thread.sleep(1100);
        assertTrue(interceptor.preHandle(request, response, new Object()));
    }

    @Test
    public void testSeparateLimitsPerIP() throws Exception {
        ConcurrentHashMap<String, RateLimitInterceptor.Entry> store = new ConcurrentHashMap<>();
        RateLimitInterceptor interceptor = new RateLimitInterceptor(store, 1, 60);

        HttpServletRequest req2 = mock(HttpServletRequest.class);
        when(req2.getRemoteAddr()).thenReturn("10.0.0.2");

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertTrue(interceptor.preHandle(req2, response, new Object()));
    }
}
