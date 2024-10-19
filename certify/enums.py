from enum import Enum

class StatusEnum(Enum):
    SUCCESS = "success"
    ERROR = "error"
    FAILED = "failed"

class MessageEnum(Enum):
    REGISTRATION_SUCCESSFUL = "Registration successful."
    LOGIN_SUCCESSFUL = "Login successful."
    LOGOUT_SUCCESSFUL = "Logout successful."
    INVALID_CREDENTIALS = "Invalid email or password."
    ACCOUNT_NOT_FOUND = "Account not found."
    EMAIL_ALREADY_EXISTS = "Email already registered."
    OTP_VERIFICATION_FAILED = "OTP verification failed."
    OTP_ALREADY_VARIFIED="OTP has already been verified."
    INVALID_OTP = "Invalid OTP provided."
    PASSWORD_RESET_SUCCESSFUL = "Password reset successfully."
    PASSWORD_RESET_FAILED = "Password reset failed."
    OTP_SENT = "OTP has been sent to your registered email."
    OTP_RESENT = "OTP has been resent."
    EMAIL_VERIFIED = "Email verified successfully."
    EMAIL_VERIFICATION_FAILED = "Email verification failed."
    OTP_RESENT_TIME_LIMIT="Please wait before requesting a new OTP."
    NO_AUTH_CODE_PROVIDED="No code provided"
    FAILED_TO_GET_AUTH_TOKEN="Failed to get access token from Google"


class GrantTypeEnum(Enum):
    GOOGLE_AUTH_GRANT_TYPE='authorization_code'