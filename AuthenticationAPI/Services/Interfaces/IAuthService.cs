using AuthenticationAPI.DTOs;

namespace AuthenticationAPI.Services.Interfaces
{
    public interface IAuthService
    {
        public Task<ResponseDTO> RegisterAsync(RegisterDTO registerDTO, string[] role);
        public Task<AuthDTO> LoginAsync(LoginDTO loginDTO);
        public Task<AuthDTO> ConfirmEmail(string? userId, string? code);
        public  Task<ResponseDTO> ResendConfirmationEmailAsync(string email);
        public Task<string> AddToRoleAsync(AddToRoleDTO addToRoleDTO);
        public Task<ResponseDTO> ForgotPasswordAsync(string email);
        public Task<ResponseDTO> VerifyOtpAsync(VerifyOtpDTO verifyOtpDTO);
        public Task<ResponseDTO> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);



    }
}
