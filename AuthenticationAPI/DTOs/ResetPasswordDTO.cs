using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs
{
    public class ResetPasswordDTO
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }

        [Required]
        public string NewPassword { get; set; }
        [Required]
        [Compare("NewPassword",ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

    }
}
