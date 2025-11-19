using AuthenticationAPI.DTOs;

namespace AuthenticationAPI.Services.Interfaces
{
    public interface IAuthService
    {
        public Task<AuthDTO> RegisterAsync(RegisterDTO registerDTO, string[] role);
        public Task<AuthDTO> LoginAsync(LoginDTO loginDTO);

        public Task<AuthDTO> ConfirmEmail(string? userId, string? code);
        public Task<string> AddToRoleAsync(AddToRoleDTO addToRoleDTO);
    }
}
