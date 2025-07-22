package com.vova.tester.controller;

import com.vova.tester.dto.JwtResponse;
import com.vova.tester.dto.LoginRequest;
import com.vova.tester.dto.RefreshTokenRequest;
import com.vova.tester.dto.RegisterRequest;
import com.vova.tester.jwt.JwtUtils;
import com.vova.tester.model.RefreshToken;
import com.vova.tester.model.Role;
import com.vova.tester.model.User;
import com.vova.tester.repository.RefreshTokenRepository;
import com.vova.tester.repository.RoleRepository;
import com.vova.tester.repository.UserRepository;
import com.vova.tester.security.UserDetailsServiceImpl;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Collections;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserDetailsServiceImpl userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = jwtUtils.generateAccessToken(userDetails);
        String refreshToken = jwtUtils.generateRefreshToken(userDetails);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setToken(refreshToken);
        refreshTokenEntity.setUser(userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found")));

        refreshTokenEntity.setExpirydate(Instant.now().plusMillis(jwtUtils.getRefreshExpiration()));
        refreshTokenRepository.save(refreshTokenEntity);

        return  ResponseEntity.ok(new JwtResponse(accessToken, refreshToken));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username is already in use");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());

        Role userRole = roleRepository.findByName("GUEST")
                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));

        user.setRoles(Collections.singleton(userRole));
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        return refreshTokenRepository.findByToken(refreshToken)
                .map(token -> {
                    if (token.getExpirydate().isBefore(Instant.now())) {
                        refreshTokenRepository.delete(token);
                        return ResponseEntity.badRequest().body("Refresh token expired");
                    }
                    User user = token.getUser();
                    UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
                    String newAccessToken = jwtUtils.generateAccessToken(userDetails);
                    return ResponseEntity.ok(new JwtResponse(newAccessToken, refreshToken));
                })
                .orElseGet(() -> ResponseEntity.badRequest().body("Invalid refresh token"));
    }

    @PostMapping("/revoke")
    @Transactional
    public ResponseEntity<?> revokeToken(@RequestBody LoginRequest request) {
        return userRepository.findByUsername(request.getUsername())
                .map(user -> {
                    refreshTokenRepository.deleteByUserId(user.getId());
                    return ResponseEntity.ok("Refresh token revoked successfully");
                })
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @GetMapping("/protected")
    public ResponseEntity<?> protectedEndpoint(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok("protected");
    }
}
