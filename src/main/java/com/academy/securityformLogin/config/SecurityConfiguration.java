package com.academy.securityformLogin.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.academy.securityformLogin.domain.SecurityUser;
import com.academy.securityformLogin.domain.User;
import com.academy.securityformLogin.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity(debug = true)
@Slf4j
public class SecurityConfiguration {

  @Autowired
  private UserRepository userRepository;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .cors(withDefaults())
        // .csrf(csrf -> csrf.disable())
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new CookieCsrfFilter(), BasicAuthenticationFilter.class)
        .authorizeHttpRequests(authorize -> authorize
            // .requestMatchers("/api/login").permitAll()
            .requestMatchers("/csrf").permitAll()
            .anyRequest().authenticated())
        .headers(headers -> headers.frameOptions(options -> options.sameOrigin()))
        .formLogin(login -> login
            // .loginProcessingUrl("/api/login")
            .successHandler((req, resp, authentication) -> {
              writeJsonResponse(resp, "success");
            })

            .failureHandler((req, resp, authentication) -> {
              writeJsonResponse(resp, "failure");
            }));
    return http.build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"));
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> {
      // 根据用户名查询用户信息，这里假设使用userRepository来获取用户信息
      return userRepository
          .findByUsername(username)
          .map(SecurityUser::new)
          .orElseThrow(() -> new UsernameNotFoundException("Username not found: " + username));
    };
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public CommandLineRunner init(UserRepository userRepository, PasswordEncoder encoder) {
    return args -> {
      // 在此处编写初始化代码
      System.out.println("Initialization code here...");

      // 初始化用户数据
      User user1 = new User("user1@abc.com", encoder.encode("password"), "ROLE_USER");
      userRepository.save(user1);

      User user2 = new User("user2@abc.com", encoder.encode("password"), "ROLE_USER,ROLE_ADMIN");
      userRepository.save(user2);
    };
  }

  // 创建 ObjectMapper 对象，用于将对象转换为 JSON 字符串
  ObjectMapper objectMapper = new ObjectMapper();

  // 定义方法来构造 JSON 响应并写回客户端
  private void writeJsonResponse(HttpServletResponse response, String status) throws IOException {
    // 构造要返回的 JSON 对象
    Map<String, Object> jsonResponse = new HashMap<>();
    jsonResponse.put("status", status);
    // 将 JSON 对象转换为 JSON 字符串
    String jsonString = objectMapper.writeValueAsString(jsonResponse);

    // 设置响应的 Content-Type 为 application/json
    response.setContentType("application/json");

    // 将 JSON 字符串作为响应写回客户端
    PrintWriter out = response.getWriter();
    out.write(jsonString);
    out.flush();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(Collections.singletonList("*"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    source.registerCorsConfiguration("/**", config);
    return source;
  }

}