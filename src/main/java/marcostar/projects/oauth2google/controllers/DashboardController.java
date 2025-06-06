package marcostar.projects.oauth2google.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import marcostar.projects.oauth2google.services.OAuth2TokenService;
import org.springframework.core.ResolvableType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class DashboardController {
    private static final String authorizationRequestBaseUri = "oauth2/authorization";
    Map<String, String> oauth2AuthenticationUrls = new HashMap<>();
    private final OAuth2AuthorizedClientRepository authorizedClientRepo;

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2TokenService tokenService;

    @GetMapping("/login")
    public String login(Model model, @AuthenticationPrincipal OAuth2User principal) {
        // Check if the user is already authenticated
        if (principal != null) {
            // Redirect to the dashboard if already logged in
            return "redirect:/dashboard";
        }
        Iterable<ClientRegistration> clientRegistrations = null;
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository)
                .as(Iterable.class);
        if (type != ResolvableType.NONE &&
                ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
            clientRegistrations.forEach(registration ->
                    oauth2AuthenticationUrls.put(registration.getClientName(),
                            authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
        }

        model.addAttribute("urls", oauth2AuthenticationUrls);

        // If not authenticated, return the login view
        model.addAttribute("message", "Please log in to access your dashboard.");
        return "login";
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OAuth2User principal, Model model, OAuth2AuthenticationToken auth, HttpServletRequest request) {
        // Extract user details from OAuth2User
        String username = principal.getAttribute("name");
        String email = principal.getAttribute("email");
        final var authorizedClient = authorizedClientRepo.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), auth, request);
        String token = Optional.ofNullable(authorizedClient).map(OAuth2AuthorizedClient::getAccessToken).map(OAuth2AccessToken::getTokenValue).orElse(null);
//        System.out.println(authorizedClient.getAccessToken().getTokenType().getValue());

//        OAuth2AccessToken accessToken = tokenService.getAccessToken(email);
//        OAuth2RefreshToken refreshToken = tokenService.getRefreshToken(email);

        model.addAttribute("username", username);
        model.addAttribute("email", email);
        model.addAttribute("token", token);

        // Return the dashboard view
        return "dashboard";
    }

}
