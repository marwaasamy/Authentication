using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs
{
    public class EmailConfirmationDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
