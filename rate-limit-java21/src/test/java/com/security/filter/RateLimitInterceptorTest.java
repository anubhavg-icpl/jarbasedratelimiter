package com.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitInterceptorTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        lenient().when(request.getRemoteAddr()).thenReturn("10.0.0.1");
    }

    @Test
    void allowsWithinLimit() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitInterceptor.Entry>();
        var interceptor = new RateLimitInterceptor(store, 5, 60);

        for (int i = 0; i < 5; i++) {
            assertTrue(interceptor.preHandle(request, response, new Object()));
        }
    }

    @Test
    void blocksOverLimit() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitInterceptor.Entry>();
        var interceptor = new RateLimitInterceptor(store, 2, 60);

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertFalse(interceptor.preHandle(request, response, new Object()));
        verify(response).setStatus(429);
    }

    @Test
    void windowReset() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitInterceptor.Entry>();
        var interceptor = new RateLimitInterceptor(store, 1, 1);

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertFalse(interceptor.preHandle(request, response, new Object()));

        Thread.sleep(1100);
        assertTrue(interceptor.preHandle(request, response, new Object()));
    }

    @Test
    void separateLimitsPerIP() throws Exception {
        var store = new ConcurrentHashMap<String, RateLimitInterceptor.Entry>();
        var interceptor = new RateLimitInterceptor(store, 1, 60);

        HttpServletRequest req2 = mock(HttpServletRequest.class);
        when(req2.getRemoteAddr()).thenReturn("10.0.0.2");

        assertTrue(interceptor.preHandle(request, response, new Object()));
        assertTrue(interceptor.preHandle(req2, response, new Object()));
    }
}
