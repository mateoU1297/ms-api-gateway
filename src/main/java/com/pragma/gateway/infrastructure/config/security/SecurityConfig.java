package com.pragma.gateway.infrastructure.config.security;

import com.pragma.gateway.exceptionhandler.CustomAccessDeniedHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    private static final String[] PUBLIC_PATHS = {
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/webjars/**",
            "/v3/api-docs/**",
            "/api/v1/users/auth/login",
            "/api/v1/users/v3/api-docs/**",
            "/api/v1/restaurants/v3/api-docs/**",
            "/actuator/health"
    };

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(PUBLIC_PATHS).permitAll()

                        .pathMatchers("/api/v1/users/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/users/owners/**").hasRole("OWNER")
                        .pathMatchers("/api/v1/users/employees/**").hasAnyRole("OWNER", "EMPLOYEE")
                        .pathMatchers("/api/v1/users/clients/**").hasRole("CLIENT")

                        .pathMatchers("/api/v1/restaurants/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/restaurants/owner/**").hasRole("OWNER")
                        .pathMatchers("/api/v1/restaurants/employees/**").hasAnyRole("OWNER", "EMPLOYEE")
                        .pathMatchers("/api/v1/restaurants/clients/**").hasRole("CLIENT")

                        .anyExchange().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}