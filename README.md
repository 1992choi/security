# [인프런] 스프링 시큐리티 완전 정복 (6.x 개정판)

## basic-01-form
- 폼 인증 - formLogin()
- 폼 인증 필터 - UsernamePasswordAuthenticationFilter
 
## basic-02-httpBasic
- 기본 인증 – httpBasic()
- 기본 인증 필터 - BasicAuthenticationFilter

## basic-03-rememberMe
- 기억하기 인증 – rememberMe()
- 기억하기 인증 필터 - RememberMeAuthenticationFilter

## basic-04-anonymous
- 익명 인증 사용자 – anonymous()

## basic-05-logout
- 로그 아웃 – logout() - 1
- 로그 아웃 – logout() - 2

## basic-06-cache
- 요청 캐시 RequestCache / SavedRequest

## basic-07-securityContext
- 인증 컨텍스트 - SecurityContext / SecurityContextHolder - 1
- 인증 컨텍스트 - SecurityContext / SecurityContextHolder - 2

## basic-08-authenticationManager
- 인증 관리자 - AuthenticationManager - 1
- 인증 관리자 - AuthenticationManager - 2

## basic-09-authenticationProvider
- 인증 제공자 - AuthenticationProvider - 1
- 인증 제공자 - AuthenticationProvider - 2

## basic-10-userDetailsService
- 사용자 상세 서비스 - UserDetailsService

## basic-11-userDetails
- 사용자 상세 - UserDetails

## basic-12-securityContextRepository
- SecurityContextRepository / SecurityContextHolderFilter - 1
- SecurityContextRepository / SecurityContextHolderFilter - 2
- SecurityContextRepository / SecurityContextHolderFilter - 3

## basic-13-springMVC
- 스프링 MVC 로그인 구현

## basic-14-maximumSessions
- 동시 세션 제어 - sessionManagement().maximumSessions()

## basic-15-sessionFixation
- 세션 고정 보호 - sessionManagement().sessionFixation()

## basic-16-sessionCreationPolicy
- 세션 생성 정책 - sessionManagement().sessionCreationPolicy()

## basic-17-sessionManagementFilter
- SessionManagementFilter / ConcurrentSessionFilter - 1
- SessionManagementFilter / ConcurrentSessionFilter - 2

## basic-18-exceptionHandling
- 예외 처리 - exceptionHandling()
- 예외 필터 - ExceptionTranslationFilter

## basic-19-cors
- CORS (Cross Origin Resource Sharing) - 1
- CORS (Cross Origin Resource Sharing) - 2

## basic-20-csrf
- CSRF (Cross Site Request Forgery)

## basic-21-csrfToken
- CSRF 토큰 유지 및 검증 - 1
- CSRF 토큰 유지 및 검증 - 2
- CSRF 토큰 유지 및 검증 - 3

## basic-22-csrfEx
- CSRF 통합

## basic-23-sameSite
- SameSite

## basic-24-authorizeHttpRequests
- 요청 기반 권한 부여 - HttpSecurity.authorizeHttpRequests() - 1
- 요청 기반 권한 부여 - HttpSecurity.authorizeHttpRequests() - 2

## basic-25-expression
- 표현식 및 커스텀 권한 구현

## basic-26-securityMatcher
- 요청 기반 권한 부여 - HttpSecurity.securityMatcher()

## basic-27-PreAuthorize&PostAuthorize
- 메서드 기반 권한 부여 - @PreAuthorize, @PostAuthorize

## basic-28-PreFilter&PostFilter
- 메서드 기반 권한 부여 - @PreFilter, @PostFilter

## basic-29-Secured&JSR-250
- 메서드 기반 권한 부여 - @Secured, JSR-250 및 부가 기능

## basic-30-staticResource
- 정적 자원 관리

## basic-31-hierarchy
- 계층적 권한 - RoleHierarchy

## basic-32-authorization
- 인가 – Authorization

## basic-33-authorityAuthorizationManager
- 요청 기반 인가 관리자 - AuthorityAuthorizationManager 외 클래스 구조 이해 - 1
- 요청 기반 인가 관리자 - AuthorityAuthorizationManager 외 클래스 구조 이해 - 2

## basic-34-customAuthorizationManager
- 요청 기반 Custom AuthorizationManager 구현

## basic-35-requestMatcherDelegatingAuthorizationManager
- RequestMatcherDelegatingAuthorizationManager로 인가 설정 응용하기

## basic-36-methodAuthorization
- 메서드 기반 인가 관리자 - PreAuthorizeAuthorizationManager 외 클래스 구조 이해 - 1
- 메서드 기반 인가 관리자 - PreAuthorizeAuthorizationManager 외 클래스 구조 이해 - 2

## basic-37-customAuthorizationManager
- 메서드 기반 Custom AuthorizationManager 구현

## basic-38-pointcut
- 포인트 컷 메서드 보안 구현하기 - AspectJExpressionPointcut / ComposablePointcut

## basic-39-aop
- AOP 메서드 보안 구현하기 - MethodInterceptor, Pointcut, Advisor

## basic-40-authenticationEvents
- 인증 이벤트 - Authentication Events

## basic-41-authenticationEventPublisher
- 인증 이벤트 - AuthenticationEventPublisher 활용

## basic-42-authorizationEvents
- 인가 이벤트 - Authorization Events

## basic-43-securityContextHolderAwareRequestFilter
- Servlet API 통합 - SecurityContextHolderAwareRequestFilter

## basic-44-authenticationPrincipal
- Spring MVC 통합 - @AuthenticationPrincipal

## basic-45-webAsyncManagerIntegrationFilter
- Spring MVC 비동기 통합 - WebAsyncManagerIntegrationFilter