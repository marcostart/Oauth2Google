package marcostar.projects.oauth2google.configs;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import marcostar.projects.oauth2google.services.OAuth2TokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final OAuth2TokenService tokenService;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
        Map<String, Object> attributes = oauth2Token.getPrincipal().getAttributes();
        String userEmail = (String) attributes.get("email");

        // Récupérer les jetons OAuth2 depuis la session
//        OAuth2AuthorizedClient authorizedClient = getAuthorizedClient(oauth2Token, request);
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                oauth2Token.getAuthorizedClientRegistrationId(),
                oauth2Token.getName()
        );
        if (authorizedClient != null) {
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

            tokenService.storeTokens(userEmail, accessToken, refreshToken);

//            String redirectUrl = "http://localhost:4200/auth/callback";
            String redirectUrl = "http://localhost:8080/dashboard";
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        }
    }

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication,
                                                       HttpServletRequest request) {
        OAuth2AuthorizedClientService clientService =
                (OAuth2AuthorizedClientService) request.getServletContext().getAttribute("oauth2AuthorizedClientService");

        return clientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName()
        );
    }
}
