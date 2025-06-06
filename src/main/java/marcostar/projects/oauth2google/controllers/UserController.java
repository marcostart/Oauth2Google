package marcostar.projects.oauth2google.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import marcostar.projects.oauth2google.services.OAuth2TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final OAuth2AuthorizedClientRepository authorizedClientRepo;

    private final OAuth2TokenService tokenService;

    @GetMapping("/info")
    public Map<String, Object> userInfo(OAuth2AuthenticationToken authentication) {
        // Return the user's attributes as a map
        return authentication.getPrincipal().getAttributes();
    }

    @GetMapping("/tokens")
    public ResponseEntity<?> getTokens(Authentication authentication, OAuth2AuthenticationToken auth, HttpServletRequest request) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final var authorizedClient = authorizedClientRepo.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), auth, request);
        OAuth2AccessToken accessToken = Optional.ofNullable(authorizedClient).map(OAuth2AuthorizedClient::getAccessToken).orElse(null);
        OAuth2RefreshToken refreshToken = Optional.ofNullable(authorizedClient).map(OAuth2AuthorizedClient::getRefreshToken).orElse(null);

//        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
//        String userEmail = (String) oauth2Token.getPrincipal().getAttributes().get("email");
//
//        OAuth2AccessToken accessToken = tokenService.getAccessToken(userEmail);
//        OAuth2RefreshToken refreshToken = tokenService.getRefreshToken(userEmail);
//
        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Map<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", accessToken.getTokenValue());
        tokens.put("token_type", accessToken.getTokenType().getValue());
        tokens.put("expires_at", accessToken.getExpiresAt());
        tokens.put("scopes", accessToken.getScopes());

        if (refreshToken != null) {
            tokens.put("refresh_token", refreshToken.getTokenValue());
        }

        return ResponseEntity.ok(tokens);
    }
}
