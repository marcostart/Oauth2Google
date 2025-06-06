package marcostar.projects.oauth2google.services;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OAuth2TokenService {
    private final Map<String, OAuth2AccessToken> userTokens = new ConcurrentHashMap<>();
    private final Map<String, OAuth2RefreshToken> refreshTokens = new ConcurrentHashMap<>();

    public void storeTokens(String userEmail, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
        userTokens.put(userEmail, accessToken);
        if (refreshToken != null) {
            refreshTokens.put(userEmail, refreshToken);
        }
    }

    public OAuth2AccessToken getAccessToken(String userEmail) {
        return userTokens.get(userEmail);
    }

    public OAuth2RefreshToken getRefreshToken(String userEmail) {
        return refreshTokens.get(userEmail);
    }
}
