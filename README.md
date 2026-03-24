# KBA - Centralized API Rate Limiting for Java Applications

## 1. Purpose

This document provides a centralized rate limiting implementation for Java-based APIs to:

- Prevent API abuse and Denial of Service (DoS)
- Protect sensitive APIs (login, OTP)
- Control excessive traffic
- Improve application stability

This solution is:

- **Centralized** (applies to all APIs)
- **Minimal code change**
- **Framework independent**
- **Easy to deploy** across environments

This repository contains two complete POC implementations:

| POC | Java Version | Servlet API | Tomcat | Test Framework |
|-----|-------------|-------------|--------|----------------|
| `rate-limit-java8/` | Java 8 | `javax.servlet` 3.1 | 8.5 | JUnit 4 + Mockito 4 |
| `rate-limit-java21/` | Java 21 | `jakarta.servlet` 6.0 | 10.1 | JUnit 5 + Mockito 5 |

## 2. Scope

### Supported Application Servers

- Apache Tomcat
- JBoss EAP / WildFly

### Supported Environments

- Windows
- RHEL / Linux

### Supported Frameworks

- Servlet-based applications
- Spring Framework (Non-Boot)
- Jersey (JAX-RS)

## 3. How Rate Limiting Works

### Example

Configuration:

```properties
rate.limit.permit=10
rate.limit.windowSeconds=60
```

Meaning:

- First 10 requests --> allowed
- 11th request --> blocked
- After 60 seconds --> counter resets

### Processing Flow

```
Client Request
   |
   v
Rate Limit Component
   |
   v
Check Counter
   |
   +---> Allowed (counter < limit) ---> Forward to Application
   |
   +---> Blocked (counter >= limit) ---> HTTP 429 Too Many Requests
```

## 4. Configuration

### File Name

`rate-limit.properties`

### File Location (IMPORTANT)

```
WEB-INF/classes/rate-limit.properties
```

In Maven projects, place at: `src/main/resources/rate-limit.properties`

### Content

```properties
rate.limit.mode=IP
rate.limit.permit=100
rate.limit.windowSeconds=60
```

### Configuration Reference

| Property | Description | Values |
|----------|-------------|--------|
| `rate.limit.mode` | Rate limiting scope | `IP` (per client) or `GLOBAL` (all clients share one counter) |
| `rate.limit.permit` | Max allowed requests per window | Any positive integer |
| `rate.limit.windowSeconds` | Time window in seconds | Any positive integer |

## 5. Implementation Options

### 5.1 Option 1: javax.servlet Filter (Recommended Universal Solution)

**Why This is Recommended:**

- Works in all servlet-based applications
- No framework dependency
- Minimal integration effort

#### Step 1: Create Java Class

**File Path:** `src/main/java/com/security/filter/RateLimitingFilter.java`

```java
package com.security.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitingFilter implements Filter {

    private static class Entry {
        int count;
        long windowStart;
    }

    private static final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

    private String mode = "IP";
    private int limit = 100;
    private int windowSec = 60;

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

    private String getKey(HttpServletRequest request) {

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
```

#### Step 2: Update web.xml

**File Path:**

- Tomcat: `<TOMCAT_HOME>/webapps/<app>/WEB-INF/web.xml`
- JBoss: `<JBOSS_HOME>/standalone/deployments/<app>.war/WEB-INF/web.xml`

**Configuration:**

```xml
<filter>
    <filter-name>RateLimitingFilter</filter-name>
    <filter-class>com.security.filter.RateLimitingFilter</filter-class>
</filter>

<filter-mapping>
    <filter-name>RateLimitingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

**How It Works:**

1. Every request passes through the filter
2. Counter is maintained in memory per key (IP or GLOBAL)
3. Request is blocked with HTTP 429 if limit is exceeded
4. `Retry-After` header tells the client when to retry

### 5.2 Option 2: jakarta.servlet

**When to Use:**

- Tomcat 10+ / Jakarta EE 9+
- Latest enterprise applications

**Change Only Imports** (all logic remains identical):

```java
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
```

> See `rate-limit-java21/` for the complete implementation.

### 5.3 Option 3: Spring Framework (Non-Boot)

> **Important:** Interceptor will NOT work unless registered.

#### Step 1: Create Interceptor

**Path:** `src/main/java/com/security/filter/RateLimitInterceptor.java`

```java
package com.security.filter;

import org.springframework.web.servlet.HandlerInterceptor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitInterceptor implements HandlerInterceptor {

    private static class Entry {
        int count;
        long windowStart;
    }

    private static final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

    private int limit = 100;
    private int windowSec = 60;

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
```

#### Step 2: Register Interceptor

**Path:** `src/main/java/com/security/config/WebConfig.java`

```java
package com.security.config;

import com.security.filter.RateLimitInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RateLimitInterceptor())
                .addPathPatterns("/**");
    }
}
```

### 5.4 Option 4: Jersey (JAX-RS)

> **Important:** Filter must be registered or it will NOT work.

#### Step 1: Create Filter

**Path:** `src/main/java/com/security/filter/RateLimitFilter.java`

```java
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

    private static class Entry {
        int count;
        long windowStart;
    }

    private static final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

    private String mode = "IP";
    private int limit = 100;
    private int windowSec = 60;

    public RateLimitFilter() {
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

    private String getKey(ContainerRequestContext ctx) {

        if ("GLOBAL".equalsIgnoreCase(mode)) return "global";

        String ip = ctx.getHeaderString("X-Forwarded-For");

        if (ip == null || ip.isEmpty()) {
            ip = "unknown";
        }

        return "ip:" + ip;
    }
}
```

#### Step 2: Register Filter (web.xml)

```xml
<init-param>
    <param-name>jersey.config.server.provider.classnames</param-name>
    <param-value>com.security.filter.RateLimitFilter</param-value>
</init-param>
```

## 6. Quick Start

### Prerequisites

- Docker and Docker Compose installed

### Start Both POCs

```bash
docker compose up --build -d
```

This starts:

- **Java 8 POC** on `http://localhost:8081`
- **Java 21 POC** on `http://localhost:8082`

### Test Manually

```bash
# Java 8
curl -X GET http://localhost:8081/api/test

# Java 21
curl -X GET http://localhost:8082/api/test
```

### Stop

```bash
docker compose down
```

## 7. Running E2E Tests

### Run All Tests

```bash
./test-e2e-all.sh
```

### Run Individual Tests

```bash
# Java 8 only
./test-e2e-java8.sh [PORT] [PERMIT] [WINDOW]
./test-e2e-java8.sh 8081 5 30

# Java 21 only
./test-e2e-java21.sh [PORT] [PERMIT] [WINDOW]
./test-e2e-java21.sh 8082 5 30
```

### What the E2E Tests Verify

| Test | Description | Expected |
|------|-------------|----------|
| Basic Response | GET /api/test returns valid JSON | HTTP 200 |
| Within Limit | Requests 1 to N pass through | HTTP 200 |
| Over Limit | Request N+1 is blocked | HTTP 429 |
| Error Body | Blocked response contains error message | `{"message":"Too many requests"}` |
| Retry-After | Blocked response includes header | `Retry-After: <seconds>` |
| X-Forwarded-For | Different proxy IP gets fresh counter | HTTP 200 |
| Per-IP Isolation | Each IP has independent limit | HTTP 429 only for exhausted IP |
| Window Reset | Counter resets after time window expires | HTTP 200 |

### Running Unit Tests

```bash
# Java 8 (18 tests)
cd rate-limit-java8
docker build --target build -t java8-test .
docker run --rm java8-test mvn test -B

# Java 21 (18 tests)
cd rate-limit-java21
docker build --target build -t java21-test .
docker run --rm java21-test mvn test -B
```

## 8. Deployment

### Tomcat

| OS | Path |
|----|------|
| Windows | `C:\apache-tomcat\webapps\` |
| Linux | `/opt/tomcat/webapps/` |

### JBoss

| OS | Path |
|----|------|
| Windows | `C:\jboss\standalone\deployments\` |
| Linux | `/opt/jboss/standalone/deployments/` |

## 9. Security Considerations

- Validate proxy before trusting `X-Forwarded-For`
- `GLOBAL` mode is JVM-specific (per application instance)
- Use distributed cache (Redis, Hazelcast) for multi-server deployments

## 10. Performance Impact

- Very low overhead
- Uses in-memory `ConcurrentHashMap`
- Suitable for medium traffic

## 11. Rollback Plan

- **Remove filter** from `web.xml` and redeploy, OR
- **Increase limit** in `rate-limit.properties` and restart

## 12. Project Structure

```
jarbasedratelimiter/
|-- docker-compose.yml
|-- test-e2e-all.sh
|-- test-e2e-java8.sh
|-- test-e2e-java21.sh
|-- rate-limit-java8/
|   |-- Dockerfile
|   |-- pom.xml
|   +-- src/
|       |-- main/
|       |   |-- java/com/security/
|       |   |   |-- filter/
|       |   |   |   |-- RateLimitingFilter.java    (javax.servlet)
|       |   |   |   |-- RateLimitInterceptor.java  (Spring)
|       |   |   |   +-- RateLimitFilter.java        (Jersey JAX-RS)
|       |   |   |-- config/
|       |   |   |   +-- WebConfig.java
|       |   |   +-- servlet/
|       |   |       +-- TestServlet.java
|       |   |-- resources/
|       |   |   +-- rate-limit.properties
|       |   +-- webapp/WEB-INF/
|       |       +-- web.xml
|       +-- test/
|           +-- java/com/security/filter/
|               |-- RateLimitingFilterTest.java
|               |-- RateLimitInterceptorTest.java
|               +-- RateLimitFilterTest.java
+-- rate-limit-java21/
    |-- Dockerfile
    |-- pom.xml
    +-- src/
        |-- main/
        |   |-- java/com/security/
        |   |   |-- filter/
        |   |   |   |-- RateLimitingFilter.java    (jakarta.servlet)
        |   |   |   |-- RateLimitInterceptor.java  (Spring 6)
        |   |   |   +-- RateLimitFilter.java        (Jersey 3)
        |   |   |-- config/
        |   |   |   +-- WebConfig.java
        |   |   +-- servlet/
        |   |       +-- TestServlet.java
        |   |-- resources/
        |   |   +-- rate-limit.properties
        |   +-- webapp/WEB-INF/
        |       +-- web.xml
        +-- test/
            +-- java/com/security/filter/
                |-- RateLimitingFilterTest.java
                |-- RateLimitInterceptorTest.java
                +-- RateLimitFilterTest.java
```
