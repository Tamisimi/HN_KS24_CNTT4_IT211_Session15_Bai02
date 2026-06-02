package org.example.session15.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Vô hiệu hóa CSRF cho REST API (an toàn khi dùng token)
            .csrf(csrf -> csrf.disable())

            // Cấu hình phân quyền
            .authorizeHttpRequests(authorize -> authorize
                // Công khai: Đăng ký và Đăng nhập
                .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()

                // Tất cả các API khác phải xác thực
                .requestMatchers("/api/**").authenticated()

                // Các request khác (nếu có) có thể điều chỉnh sau
                .anyRequest().authenticated()
            )

            // Tắt formLogin vì đây là REST API (không dùng trang web form)
            .formLogin(form -> form.disable())

            // Cấu hình stateless (không dùng session)
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );

        return http.build();
    }

    // ================== In-Memory Users cho Testing ==================
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
