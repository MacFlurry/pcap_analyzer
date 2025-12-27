# Password Reset Guide

This document describes the password reset functionality in PCAP Analyzer, covering both self-service and administrator-initiated flows.

## Self-Service Password Reset (User)

Users who have forgotten their password can regain access to their account using the following process:

1.  **Request Reset**: On the Login page, click the **"Mot de passe oublié ?"** link.
2.  **Email Submission**: Enter your registered email address. For security, the system provides a generic success message regardless of whether the email exists.
3.  **Check Email**: If an active and approved account matches the email, you will receive a message with a unique reset link.
    -   **Validity**: The link is valid for **60 minutes**.
    -   **Single Use**: Each link can only be used once.
4.  **New Password**: Click the link to reach the reset page. You will see your masked email (e.g., `u***@example.com`) to confirm the account.
5.  **Validation**: Enter a new password. It must meet the security policy:
    -   Minimum **12 characters**.
    -   Strength score of **3/4 or higher** (as measured by the strength meter).
    -   Cannot be one of your last **5 passwords**.
6.  **Success**: Once submitted, you will be redirected to the login page to access your account with the new password.

## Administrator-Initiated Reset

Administrators can reset passwords for regular users through the Admin Panel.

1.  **Locate User**: In the **Admin Panel**, find the user in the table.
2.  **Reset Action**: Click the **Key icon** (Reset Password) in the actions column.
3.  **Options**:
    -   **Send by Email**: The user receives a temporary password via email.
    -   **Manual**: If unchecked, the temporary password is displayed on the screen for the administrator to copy and communicate manually.
4.  **Force Password Change**: After an admin reset, the user is **required** to change their password immediately upon their next login.
    - After successfully changing the password, the user is redirected to the home page.
    - **Note**: The user menu (profile icon and logout button) will be visible after the password change.

## Security Features

-   **Anti-Enumeration**: Success messages are generic to prevent attackers from discovering registered email addresses.
-   **Rate Limiting**: Password reset requests are limited per IP to prevent spam and brute-force attempts.
-   **Cryptographic Entropy**: Reset tokens are 256-bit random strings, hashed using SHA-256 in the database.
-   **Audit Logging**: All reset requests and completions are logged at the `WARNING` level for security monitoring.
-   **Admin Protection**: Administrators cannot reset other administrator accounts via the UI; they must use the self-service flow for better accountability.
