package com.expensepro.expensemanagement.security;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.expensepro.expensemanagement.model.Role;
import com.expensepro.expensemanagement.model.Status;
import com.expensepro.expensemanagement.model.User;
import com.expensepro.expensemanagement.repository.UserRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;  // Repository to interact with the users table
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    public OAuth2SuccessHandler(JwtTokenProvider jwtTokenProvider, UserRepository userRepository, OAuth2AuthorizedClientService authorizedClientService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        // Get the email from the OAuth2User
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

            // Determine registrationId (provider), e.g., "github"
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        String principalName = oauthToken.getName();

        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(registrationId, principalName);

        if (email == null && "github".equalsIgnoreCase(registrationId)) {
            String accessToken = authorizedClient.getAccessToken().getTokenValue();

            // Prepare the headers
            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setAccept(java.util.Collections.singletonList(org.springframework.http.MediaType.APPLICATION_JSON));

            org.springframework.http.HttpEntity<String> entity = new org.springframework.http.HttpEntity<>(headers);

            org.springframework.web.client.RestTemplate restTemplate = new org.springframework.web.client.RestTemplate();

            java.util.List<java.util.Map<String, Object>> emails = restTemplate.exchange(
                "https://api.github.com/user/emails",
                org.springframework.http.HttpMethod.GET,
                entity,
                new org.springframework.core.ParameterizedTypeReference<java.util.List<java.util.Map<String, Object>>>() {}
            ).getBody();

            if (emails != null) {
                for (java.util.Map<String, Object> mail : emails) {
                    Boolean primary = (Boolean) mail.get("primary");
                    Boolean verified = (Boolean) mail.get("verified");
                    if (primary != null && primary && verified != null && verified) {
                        email = (String) mail.get("email");
                        break;
                    }
                }
            }
        }

        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");
        String githubUsername = oAuth2User.getAttribute("login");

         // For GitHub or other providers where given_name/family_name might be missing
        if (firstName == null && lastName == null) {
            String fullName = oAuth2User.getAttribute("name");
            if (fullName != null) {
                String[] parts = fullName.split(" ", 2);
                firstName = parts.length > 0 ? parts[0] : null;
                lastName = parts.length > 1 ? parts[1] : null;
            }
        }
        // Ensure firstName is never null or empty before saving to DB
        if (firstName == null || firstName.isEmpty()) {
            if (email != null && !email.isEmpty()) {
                firstName = githubUsername;  // fallback to email username
            } else {
                firstName = "User";  // generic fallback
            }
        }

        if (lastName == null) {
            lastName = "";  // lastName can be empty but not null
        }

        // Generate initials - 1 or 2 characters based on available names
        String initials = "";
        if (firstName != null && !firstName.isEmpty()) {
            initials += firstName.charAt(0);
        }
        if (!lastName.isEmpty()) {
            initials += lastName.charAt(0);
        }

        // If both names are missing, fallback to first letter of email or empty string
        if (initials.isEmpty() && email != null && !email.isEmpty()) {
            initials += email.charAt(0);
        }

        // Check if user exists in the database
        Optional<User> optionalUser = userRepository.findByEmail(email); // Returns an Optional

        // If the user does not exist, create a new user
       if (!optionalUser.isPresent()) {
            // Create new user object and set necessary fields
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setFirstName(firstName);
            newUser.setLastName(lastName);
            newUser.setInitials(initials);
            newUser.setStatus(Status.ACTIVE);  // Set the default status as active
            newUser.setRole(Role.EMPLOYEE);  // Default role (change according to your logic)
            newUser.setCreatedAt(new Timestamp(System.currentTimeMillis()));  // Set created timestamp
            newUser.setUpdatedAt(new Timestamp(System.currentTimeMillis()));  // Set updated timestamp

            // Save the new user in the database
            userRepository.save(newUser);  // Save directly without storing in a variable
        }

        // Generate a JWT token for the user
        String token = jwtTokenProvider.generateToken(authentication);  // Using the full authentication object

        // Redirect to frontend with token as URL parameter
        String redirectUrl = "http://localhost:3000/employee/dashboard?token=" + token;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);

    }
}

