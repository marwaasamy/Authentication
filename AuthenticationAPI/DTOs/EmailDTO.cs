using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs
{
    public class EmailDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
