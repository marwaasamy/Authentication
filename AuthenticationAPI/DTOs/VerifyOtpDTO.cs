using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs
{
    public class VerifyOtpDTO
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; } 

        [Required]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP must be 6 characters long.")]
        public string Otp { get; set; } 
    }
}
