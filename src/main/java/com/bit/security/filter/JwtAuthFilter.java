package com.bit.security.filter;

import com.bit.security.model.UserDTO;
import com.bit.security.provider.JwtProvider;
import com.bit.security.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@AllArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private UserDetailsServiceImpl userDetailsService;
    private JwtProvider provider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header != null) {
            String authorizationHeader = provider.readToken(request);

            if (provider.validate(authorizationHeader)) {
                String username = provider.getUsernmae(authorizationHeader);

                UserDTO userDTO = (UserDTO) userDetailsService.loadUserByUsername(username);
                if (userDTO != null) {
                    UsernamePasswordAuthenticationToken token
                            = new UsernamePasswordAuthenticationToken(userDTO, "", userDTO.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(token);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
