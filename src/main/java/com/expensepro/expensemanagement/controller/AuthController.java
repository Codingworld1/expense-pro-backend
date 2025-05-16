package com.expensepro.expensemanagement.controller;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.expensepro.expensemanagement.dto.ErrorResponse;
import com.expensepro.expensemanagement.dto.ForgotPasswordRequest;
import com.expensepro.expensemanagement.dto.LoginRequest;
import com.expensepro.expensemanagement.dto.LoginResponse;
import com.expensepro.expensemanagement.dto.ResetPasswordRequest;
import com.expensepro.expensemanagement.model.PasswordResetToken;
import com.expensepro.expensemanagement.model.User;
import com.expensepro.expensemanagement.repository.PasswordResetTokenRepository;
import com.expensepro.expensemanagement.repository.UserRepository;
import com.expensepro.expensemanagement.security.JwtTokenProvider;
import com.expensepro.expensemanagement.security.OAuth2SuccessHandler;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000")
public class AuthController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private OAuth2SuccessHandler oauth2SuccessHandler;

    private User loadUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("User not found with email: " + email));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            User user = loadUserByEmail(loginRequest.getEmail());

            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid email or password");
            }

            if (!user.getRole().name().equalsIgnoreCase(loginRequest.getRole())) {
                throw new BadCredentialsException("Unauthorized role access");
            }

            String token = jwtTokenProvider.generateToken(user);
            return ResponseEntity.ok(new LoginResponse(token));

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse(ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("An unexpected error occurred"));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        return userRepository.findByEmail(email)
                .map(user -> {
                    String token = UUID.randomUUID().toString();
                    LocalDateTime expiry = LocalDateTime.now().plusMinutes(15);

                    PasswordResetToken resetToken = new PasswordResetToken(token, expiry, user);
                    passwordResetTokenRepository.save(resetToken);

                    String resetLink = "http://localhost:3000/reset-password?token=" + token;

                    MimeMessage message = mailSender.createMimeMessage();
                    try {
                        MimeMessageHelper helper = new MimeMessageHelper(message, true);
                        helper.setTo(email);
                        helper.setSubject("Reset your password - ExpensePro");
                        helper.setFrom("srihari.desai12@gmail.com");
                        helper.setText("<html><body>" +
                                "<p>Hi " + user.getFirstName() + ",</p>" +
                                "<p>We received a request to reset your password. Click the link below to proceed:</p>" +
                                "<p><a href=\"" + resetLink + "\">Reset Password</a></p>" +
                                "<p>This link will expire in 15 minutes.</p>" +
                                "<p>If you didn't request a reset, please ignore this email.</p>" +
                                "<p>Regards,<br>ExpensePro Team</p>" +
                                "</body></html>", true);

                        mailSender.send(message);
                        return ResponseEntity.ok("Password reset link sent to your email.");
                    } catch (MessagingException | MailException e) {
                        e.printStackTrace();
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body("Failed to send email. Please try again later.");
                    }
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("Email not found"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        String token = request.getToken();
        String newPassword = request.getNewPassword();

        return passwordResetTokenRepository.findByToken(token)
                .map(resetToken -> {
                    if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token has expired.");
                    }

                    User user = resetToken.getUser();
                    user.setPassword(passwordEncoder.encode(newPassword));
                    userRepository.save(user);
                    passwordResetTokenRepository.delete(resetToken);

                    return ResponseEntity.ok("Password has been reset successfully.");
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token."));
    }


}
