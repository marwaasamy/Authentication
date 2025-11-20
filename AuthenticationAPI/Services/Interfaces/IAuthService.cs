using AuthenticationAPI.DTOs;

namespace AuthenticationAPI.Services.Interfaces
{
    public interface IAuthService
    {
        public Task<ResponseDTO> RegisterAsync(RegisterDTO registerDTO, string[] role);
        public Task<AuthDTO> LoginAsync(LoginDTO loginDTO);

        public Task<AuthDTO> ConfirmEmail(string? userId, string? code);

        Task<ResponseDTO> ResendConfirmationEmailAsync(string email);
        public Task<string> AddToRoleAsync(AddToRoleDTO addToRoleDTO);
    }
}
