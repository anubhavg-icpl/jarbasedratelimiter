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

---

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

### POC Implementations Included

| POC | Java | Servlet API | Tomcat | Tests |
|-----|------|-------------|--------|-------|
| `rate-limit-java8/` | Java 8 | `javax.servlet` 3.1 | 8.5 | JUnit 4 + Mockito 4 (18 tests) |
| `rate-limit-java21/` | Java 21 | `jakarta.servlet` 6.0 | 10.1 | JUnit 5 + Mockito 5 (18 tests) |

---

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

---

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

---

## 5. Implementation Options

### 5.1 Option 1: javax.servlet Filter (Recommended Universal Solution)

**Why This is Recommended:**

- Works in all servlet-based applications
- No framework dependency
- Minimal integration effort

#### Step 1: Create Java Class

**File Path:** `src/main/java/com/security/filter/RateLimitingFilter.java`

**Java 8 version** (`javax.servlet`):

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

---

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

---

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

---

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

---

## 6. Quick Start

### Prerequisites

- Docker installed

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

---

## 7. Deployment

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

---

## 8. Testing

### 8.1 Unit Tests (36 total)

```bash
# Java 8 (18 tests - JUnit 4)
cd rate-limit-java8
docker build --target build -t java8-test .
docker run --rm java8-test mvn test -B

# Java 21 (18 tests - JUnit 5)
cd rate-limit-java21
docker build --target build -t java21-test .
docker run --rm java21-test mvn test -B
```

### 8.2 E2E Tests

```bash
# Run all E2E tests
./test-e2e-all.sh

# Run individually
./test-e2e-java8.sh [PORT] [PERMIT] [WINDOW]
./test-e2e-java21.sh [PORT] [PERMIT] [WINDOW]

# Example with defaults
./test-e2e-java8.sh 8081 5 30
```

### 8.3 E2E Test Coverage

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

---

## 9. Security Considerations

- Validate proxy before trusting `X-Forwarded-For`
- `GLOBAL` mode is JVM-specific (per application instance)
- Use distributed cache (Redis, Hazelcast) for multi-server deployments

---

## 10. Performance Impact

- Very low overhead
- Uses in-memory `ConcurrentHashMap`
- Suitable for medium traffic

---

## 11. Rollback Plan

- **Remove filter** from `web.xml` and redeploy, OR
- **Increase limit** in `rate-limit.properties` and restart

---

## 12. Complete Source Code

### 12.1 Project Structure

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
|       |-- main/java/com/security/
|       |   |-- filter/
|       |   |   |-- RateLimitingFilter.java
|       |   |   |-- RateLimitInterceptor.java
|       |   |   +-- RateLimitFilter.java
|       |   |-- config/WebConfig.java
|       |   +-- servlet/TestServlet.java
|       |-- main/resources/rate-limit.properties
|       |-- main/webapp/WEB-INF/web.xml
|       +-- test/java/com/security/filter/
|           |-- RateLimitingFilterTest.java
|           |-- RateLimitInterceptorTest.java
|           +-- RateLimitFilterTest.java
+-- rate-limit-java21/
    |-- Dockerfile
    |-- pom.xml
    +-- src/
        |-- main/java/com/security/
        |   |-- filter/
        |   |   |-- RateLimitingFilter.java
        |   |   |-- RateLimitInterceptor.java
        |   |   +-- RateLimitFilter.java
        |   |-- config/WebConfig.java
        |   +-- servlet/TestServlet.java
        |-- main/resources/rate-limit.properties
        |-- main/webapp/WEB-INF/web.xml
        +-- test/java/com/security/filter/
            |-- RateLimitingFilterTest.java
            |-- RateLimitInterceptorTest.java
            +-- RateLimitFilterTest.java
```

### 12.2 Infrastructure Files

#### `docker-compose.yml`

```yaml
services:
  rate-limit-java8:
    build:
      context: ./rate-limit-java8
      dockerfile: Dockerfile
    container_name: rate-limit-java8
    ports:
      - "8081:8080"
    restart: unless-stopped

  rate-limit-java21:
    build:
      context: ./rate-limit-java21
      dockerfile: Dockerfile
    container_name: rate-limit-java21
    ports:
      - "8082:8080"
    restart: unless-stopped
```

#### `rate-limit-java8/Dockerfile`

```dockerfile
FROM maven:3.9-eclipse-temurin-8 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -B

FROM tomcat:8.5-jre8
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /app/target/rate-limit-app.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
```

#### `rate-limit-java21/Dockerfile`

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -B

FROM tomcat:10.1-jre21
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /app/target/rate-limit-app.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
```

### 12.3 Java 8 POC - All Source Files

#### `rate-limit-java8/pom.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.security</groupId>
    <artifactId>rate-limit-java8</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>war</packaging>

    <properties>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- Servlet API -->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>3.1.0</version>
            <scope>provided</scope>
        </dependency>

        <!-- Spring Web MVC -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>5.3.30</version>
            <scope>provided</scope>
        </dependency>

        <!-- Jersey JAX-RS -->
        <dependency>
            <groupId>org.glassfish.jersey.core</groupId>
            <artifactId>jersey-server</artifactId>
            <version>2.39.1</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.glassfish.jersey.containers</groupId>
            <artifactId>jersey-container-servlet</artifactId>
            <version>2.39.1</version>
            <scope>provided</scope>
        </dependency>

        <!-- JAX-RS API -->
        <dependency>
            <groupId>javax.ws.rs</groupId>
            <artifactId>javax.ws.rs-api</artifactId>
            <version>2.1.1</version>
            <scope>provided</scope>
        </dependency>

        <!-- Test dependencies -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>4.11.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <finalName>rate-limit-app</finalName>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-war-plugin</artifactId>
                <version>3.3.2</version>
            </plugin>
        </plugins>
    </build>
</project>
```

#### `rate-limit-java8/src/main/resources/rate-limit.properties`

```properties
rate.limit.mode=IP
rate.limit.permit=100
rate.limit.windowSeconds=60
```

#### `rate-limit-java8/src/main/webapp/WEB-INF/web.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">

    <filter>
        <filter-name>RateLimitingFilter</filter-name>
        <filter-class>com.security.filter.RateLimitingFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>RateLimitingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    <servlet>
        <servlet-name>TestServlet</servlet-name>
        <servlet-class>com.security.servlet.TestServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>TestServlet</servlet-name>
        <url-pattern>/api/test</url-pattern>
    </servlet-mapping>
</web-app>
```

#### `rate-limit-java8/src/main/java/com/security/filter/RateLimitingFilter.java`

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

    // Visible for testing
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
```

#### `rate-limit-java8/src/main/java/com/security/filter/RateLimitInterceptor.java`

```java
package com.security.filter;

import org.springframework.web.servlet.HandlerInterceptor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
```

#### `rate-limit-java8/src/main/java/com/security/filter/RateLimitFilter.java`

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
```

#### `rate-limit-java8/src/main/java/com/security/config/WebConfig.java`

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

#### `rate-limit-java8/src/main/java/com/security/servlet/TestServlet.java`

```java
package com.security.servlet;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TestServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.getWriter().write("{\"status\":\"ok\",\"message\":\"Hello from Java 8 Rate Limit POC\"}");
    }
}
```

#### `rate-limit-java8/src/test/java/com/security/filter/RateLimitingFilterTest.java`

```java
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
        filter.doFilter(req1, response, chain);

        verify(chain, times(2)).doFilter(any(), eq(response));
        verify(response, atLeastOnce()).setStatus(429);
    }

    @Test
    public void testWindowResetsAfterExpiry() throws Exception {
        ConcurrentHashMap<String, RateLimitingFilter.Entry> store = new ConcurrentHashMap<>();
        RateLimitingFilter filter = new RateLimitingFilter(store, "IP", 2, 1);
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

        verify(chain).doFilter(req1, resp1);
        verify(chain).doFilter(req2, resp2);
    }
}
```

#### `rate-limit-java8/src/test/java/com/security/filter/RateLimitInterceptorTest.java`

```java
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
```

#### `rate-limit-java8/src/test/java/com/security/filter/RateLimitFilterTest.java`

```java
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
        filter.filter(ctx1);

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
        filter.filter(ctx);
        verify(ctx).abortWith(argThat(resp -> resp.getStatus() == 429));

        Thread.sleep(1100);
        ContainerRequestContext ctx2 = mock(ContainerRequestContext.class);
        when(ctx2.getHeaderString("X-Forwarded-For")).thenReturn("10.0.0.1");
        filter.filter(ctx2);
        verify(ctx2, never()).abortWith(any(Response.class));
    }
}
```

### 12.4 Java 21 POC - All Source Files

> The Java 21 POC is identical to Java 8 except for:
> - `javax.servlet` --> `jakarta.servlet`
> - `javax.ws.rs` --> `jakarta.ws.rs`
> - Spring 5.3 --> Spring 6.1
> - Jersey 2.x --> Jersey 3.x
> - JUnit 4 --> JUnit 5 (Jupiter)
> - Mockito 4 --> Mockito 5
> - Tomcat 8.5 --> Tomcat 10.1

#### `rate-limit-java21/pom.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.security</groupId>
    <artifactId>rate-limit-java21</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>war</packaging>

    <properties>
        <maven.compiler.release>21</maven.compiler.release>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>jakarta.servlet</groupId>
            <artifactId>jakarta.servlet-api</artifactId>
            <version>6.0.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>6.1.4</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.glassfish.jersey.core</groupId>
            <artifactId>jersey-server</artifactId>
            <version>3.1.5</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.glassfish.jersey.containers</groupId>
            <artifactId>jersey-container-servlet</artifactId>
            <version>3.1.5</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>jakarta.ws.rs</groupId>
            <artifactId>jakarta.ws.rs-api</artifactId>
            <version>3.1.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <finalName>rate-limit-app</finalName>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-war-plugin</artifactId>
                <version>3.4.0</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.12.1</version>
                <configuration>
                    <release>21</release>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.2.5</version>
            </plugin>
        </plugins>
    </build>
</project>
```

#### `rate-limit-java21/src/main/resources/rate-limit.properties`

```properties
rate.limit.mode=IP
rate.limit.permit=100
rate.limit.windowSeconds=60
```

#### `rate-limit-java21/src/main/webapp/WEB-INF/web.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee
         https://jakarta.ee/xml/ns/jakartaee/web-app_6_0.xsd"
         version="6.0">

    <filter>
        <filter-name>RateLimitingFilter</filter-name>
        <filter-class>com.security.filter.RateLimitingFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>RateLimitingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    <servlet>
        <servlet-name>TestServlet</servlet-name>
        <servlet-class>com.security.servlet.TestServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>TestServlet</servlet-name>
        <url-pattern>/api/test</url-pattern>
    </servlet-mapping>
</web-app>
```

#### `rate-limit-java21/src/main/java/com/security/filter/RateLimitingFilter.java`

```java
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
```

#### `rate-limit-java21/src/main/java/com/security/filter/RateLimitInterceptor.java`

```java
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
```

#### `rate-limit-java21/src/main/java/com/security/filter/RateLimitFilter.java`

```java
package com.security.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
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
```

#### `rate-limit-java21/src/main/java/com/security/config/WebConfig.java`

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

#### `rate-limit-java21/src/main/java/com/security/servlet/TestServlet.java`

```java
package com.security.servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TestServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.getWriter().write("{\"status\":\"ok\",\"message\":\"Hello from Java 21 Rate Limit POC\"}");
    }
}
```

#### `rate-limit-java21/src/test/java/com/security/filter/RateLimitingFilterTest.java`

```java
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
```

#### `rate-limit-java21/src/test/java/com/security/filter/RateLimitInterceptorTest.java`

```java
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
```

#### `rate-limit-java21/src/test/java/com/security/filter/RateLimitFilterTest.java`

```java
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
```

### 12.5 E2E Test Scripts

#### `test-e2e-all.sh`

```bash
#!/bin/bash
# Run All E2E Tests - Both Java 8 and Java 21
# Usage: ./test-e2e-all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXIT_CODE=0

echo "============================================================"
echo "  Running All E2E Tests"
echo "============================================================"
echo ""

echo ">>> Java 8 E2E Tests"
echo "------------------------------------------------------------"
if bash "$SCRIPT_DIR/test-e2e-java8.sh" 8081 5 30; then
    echo ""
    echo ">>> Java 8: ALL PASSED"
else
    echo ""
    echo ">>> Java 8: SOME TESTS FAILED"
    EXIT_CODE=1
fi

echo ""
echo ""

echo ">>> Java 21 E2E Tests"
echo "------------------------------------------------------------"
if bash "$SCRIPT_DIR/test-e2e-java21.sh" 8082 5 30; then
    echo ""
    echo ">>> Java 21: ALL PASSED"
else
    echo ""
    echo ">>> Java 21: SOME TESTS FAILED"
    EXIT_CODE=1
fi

echo ""
echo "============================================================"
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "  ALL E2E TESTS PASSED"
else
    echo "  SOME E2E TESTS FAILED"
fi
echo "============================================================"

exit $EXIT_CODE
```

#### `test-e2e-java8.sh`

```bash
#!/bin/bash
# E2E Test Script - Java 8 Rate Limiting POC
# Usage: ./test-e2e-java8.sh [PORT] [PERMIT] [WINDOW]

set -euo pipefail

PORT="${1:-8081}"
PERMIT="${2:-5}"
WINDOW="${3:-30}"
BASE="http://localhost:${PORT}"
IMAGE="rate-limit-java8-e2e"
CONTAINER="java8-e2e"
PASSED=0
FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_eq() {
    local test_name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name (expected=$expected, got=$actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (expected=$expected, got=$actual)"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local test_name="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $test_name (contains '$expected')"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (expected to contain '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_not_empty() {
    local test_name="$1" actual="$2"
    if [ -n "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name (value=$actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (empty)"
        FAILED=$((FAILED + 1))
    fi
}

echo "==========================================================="
echo "  E2E Test Suite - Java 8 Rate Limiting POC"
echo "  Port: $PORT | Permit: $PERMIT | Window: ${WINDOW}s"
echo "==========================================================="
echo ""

# Build and Start
echo -e "${YELLOW}[Setup] Building Docker image...${NC}"
docker rm -f "$CONTAINER" 2>/dev/null || true
cd "$(dirname "$0")/rate-limit-java8"

cat > src/main/resources/rate-limit.properties <<EOF
rate.limit.mode=IP
rate.limit.permit=${PERMIT}
rate.limit.windowSeconds=${WINDOW}
EOF

docker build -t "$IMAGE" . > /dev/null 2>&1
echo -e "${YELLOW}[Setup] Starting container on port $PORT...${NC}"
docker run -d --name "$CONTAINER" -p "${PORT}:8080" "$IMAGE" > /dev/null
sleep 12

if ! docker ps --format '{{.Names}}' | grep -q "$CONTAINER"; then
    echo -e "${RED}FATAL: Container failed to start${NC}"
    docker logs "$CONTAINER" 2>&1 | tail -20
    exit 1
fi
echo ""

# Test 1: Basic Response
echo "[Test 1] Basic GET response"
BODY=$(curl -X GET -s "$BASE/api/test")
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
assert_eq "HTTP status is 200" "200" "$CODE"
assert_contains "Response contains status:ok" "status" "$BODY"
echo ""

# Test 2: Requests Within Limit
echo "[Test 2] Requests within limit (${PERMIT} total allowed, 2 used above)"
REMAINING=$((PERMIT - 2))
for i in $(seq 1 "$REMAINING"); do
    CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
done
assert_eq "Last allowed request is 200" "200" "$CODE"
echo ""

# Test 3: Request Over Limit = 429
echo "[Test 3] Request over limit (should be blocked)"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
BODY=$(curl -X GET -s "$BASE/api/test")
assert_eq "Blocked request returns 429" "429" "$CODE"
assert_contains "Response body has error message" "Too many requests" "$BODY"
echo ""

# Test 4: Retry-After Header
echo "[Test 4] Retry-After header on blocked request"
RETRY_AFTER=$(curl -X GET -s -D - -o /dev/null "$BASE/api/test" 2>/dev/null | grep -i "Retry-After" | tr -d '\r' | awk '{print $2}')
assert_not_empty "Retry-After header present" "$RETRY_AFTER"
echo ""

# Test 5: X-Forwarded-For = Separate Counter
echo "[Test 5] X-Forwarded-For creates separate rate limit counter"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test")
assert_eq "New IP via X-Forwarded-For gets 200" "200" "$CODE"
echo ""

# Test 6: X-Forwarded-For IP Also Gets Rate Limited
echo "[Test 6] X-Forwarded-For IP exhaustion"
for i in $(seq 2 "$PERMIT"); do
    curl -X GET -s -o /dev/null -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test"
done
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test")
assert_eq "X-FF IP blocked after limit" "429" "$CODE"
echo ""

# Test 7: Different IPs Have Separate Limits
echo "[Test 7] Different IPs have independent counters"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 198.51.100.1" "$BASE/api/test")
assert_eq "Different IP still gets 200" "200" "$CODE"
echo ""

# Test 8: Window Reset
echo "[Test 8] Window reset after ${WINDOW} seconds"
echo -e "  ${YELLOW}Waiting $((WINDOW + 1)) seconds for window to expire...${NC}"
sleep $((WINDOW + 1))
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
assert_eq "After window reset, request returns 200" "200" "$CODE"
echo ""

# Cleanup
echo -e "${YELLOW}[Cleanup] Stopping container...${NC}"
docker rm -f "$CONTAINER" > /dev/null 2>&1

cat > src/main/resources/rate-limit.properties <<EOF
rate.limit.mode=IP
rate.limit.permit=100
rate.limit.windowSeconds=60
EOF

echo ""
echo "==========================================================="
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "==========================================================="

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
```

#### `test-e2e-java21.sh`

> Identical to `test-e2e-java8.sh` except:
> - Default port: `8082`
> - Image name: `rate-limit-java21-e2e`
> - Container name: `java21-e2e`
> - Directory: `rate-limit-java21`
> - Header says "Java 21"
