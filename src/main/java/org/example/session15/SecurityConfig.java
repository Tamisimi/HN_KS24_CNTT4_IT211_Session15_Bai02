package org.example.session15;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
                .authorizeHttpRequests(authorize -> authorize
                        // 1. Công khai - Không cần đăng nhập
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/public/**").permitAll()

                        // 2. Chỉ ADMIN mới được vào
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // 3. Các request còn lại phải đăng nhập
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .permitAll()           // Cho phép tất cả truy cập trang login
                )
                .logout(logout -> logout
                        .permitAll()
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