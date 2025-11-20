using AuthenticationAPI.DTOs;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _RoleManager;
        private readonly JWT _jwt;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt, IHttpContextAccessor httpContextAccessor, IEmailSender emailSender)
        {
            _userManager = userManager;
            _RoleManager = roleManager;
            _jwt = jwt.Value;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
        }

        public async Task<ResponseDTO> RegisterAsync(RegisterDTO registerDTO, string[] role)
        {
            if (await _userManager.FindByEmailAsync(registerDTO.Email) is not null)
            {
                return new ResponseDTO
                {
                    Message = "this Email is already registered"
                };
            }

            if (await _userManager.FindByNameAsync(registerDTO.Username) is not null)
            {
                return new ResponseDTO
                {
                    Message = "Username is already registered"
                };
            }
            ApplicationUser user = new ApplicationUser()
            {
                Email = registerDTO.Email,
                UserName = registerDTO.Username,
                FirstName = registerDTO.firstName,
                LastName = registerDTO.lastName
            };
            var result = await _userManager.CreateAsync(user, registerDTO.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));

                return new ResponseDTO { Message = errors };
            }

            await _userManager.AddToRolesAsync(user, role);

            //send Confirm Email here

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedCode = Uri.EscapeDataString(code);
            var requestAccessor = _httpContextAccessor.HttpContext.Request;         
            var returnUrl = requestAccessor.Scheme + "://" + requestAccessor.Host+
            $"/api/Auth/ConfirmEmail?userId={user.Id}&code={encodedCode}";

            var emailBody = $" <h2>Email Confirmation</h2>"+
                $"<p> Hello { System.Net.WebUtility.HtmlEncode(user.FullName)},</p>" +
                $"<p>Please confirm your email by clicking the link below:</p>" +
                $"<a href='{returnUrl}'>Confirm Email</a>"+
                $"<p>This link will expire in 24 hours.</p>";

            await _emailSender.SendEmailAsync(user.Email, "Confirm your email", emailBody);

            //var token = await CreateJWTToken(user);
            return new ResponseDTO
            {
                //IsAuthenticated = true,
                //Token = new JwtSecurityTokenHandler().WriteToken(token),
                //ExpiresOn = token.ValidTo,
                Message = "User Registered successfully. Please check your email to confirm your account.",
                RequireEmailConfirmation = true,
            };
        }

        public async Task<AuthDTO> ConfirmEmail(string? userId, string? code)
        {
            if (userId == null || code == null)
            {
                return new AuthDTO { Message = "Invalid user ID or code" };
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new AuthDTO { Message = "User not found" };
            }

            if (await _userManager.IsEmailConfirmedAsync(user))
            {
                return new AuthDTO { Message = "Email is already confirmed. You can log in." };
            }

            var decodedCode = Uri.UnescapeDataString(code);

            var result = await _userManager.ConfirmEmailAsync(user, decodedCode);

            
            
            if (result.Succeeded)
            {
                var token = await CreateJWTToken(user);
                return new AuthDTO
                {
                    IsAuthenticated = true,
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Message = "Email confirmed successfully. You can now log in.",
                    ExpiresOn = token.ValidTo,
                    UserName = user.UserName ?? string.Empty,
                    Email = user.Email ?? string.Empty,
                    FullName = user.FullName
                };
            }
            else
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                return new AuthDTO { Message = errors };
            }
        }


        public async Task<ResponseDTO> ResendConfirmationEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new ResponseDTO { Message = "User not found" , IsSuccess = false};
            }

            if (await _userManager.IsEmailConfirmedAsync(user))
            {
                return new ResponseDTO { Message = "Email is already confirmed. You can log in." , IsSuccess = false };
            }

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedCode = Uri.EscapeDataString(code);

            var requestAccessor = _httpContextAccessor.HttpContext.Request;
            var confirmationLink = requestAccessor.Scheme + "://" + requestAccessor.Host +
                $"/api/Auth/ConfirmEmail?userId={user.Id}&code={encodedCode}";

            var emailBody = $@"
                          <h2>Email Confirmation</h2>
                          <p>Hello {System.Net.WebUtility.HtmlEncode(user.FullName)},</p>
                          <p>You requested a new confirmation email. Please confirm your email by clicking the link below:</p>
                          <p><a href='{confirmationLink}'>Confirm Email</a></p>
                          <p>This link will expire in 24 hours.</p>
                          <p>If you did not request this, please ignore this email.</p>";
             
            await _emailSender.SendEmailAsync(user.Email, "Confirm your email", emailBody);

            return new ResponseDTO
            { 
                Message = "Confirmation email resent. Please check your email to confirm your account."
                , IsSuccess = true
            };
        }


        public async Task<AuthDTO> LoginAsync(LoginDTO loginDTO)
        {
            var finduser = await _userManager.FindByEmailAsync(loginDTO.Email);
            if (finduser == null || !await _userManager.CheckPasswordAsync(finduser, loginDTO.Password))
            {
                return new AuthDTO { Message = "Email or Password is incorrect" };
            }
            if (!await _userManager.IsEmailConfirmedAsync(finduser))
            {
                return new AuthDTO { Message = "Email is not confirmed. Please check your email to confirm your account." };
            }

            var token = await CreateJWTToken(finduser);

            return new AuthDTO
            {
                IsAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpiresOn = token.ValidTo,
                UserName = finduser.UserName ?? string.Empty,
                Email = finduser.Email ?? string.Empty,
                FullName = finduser.FullName
            };

        }

        public async Task<string> AddToRoleAsync(AddToRoleDTO addToRoleDTO)
        {
            var user = await _userManager.FindByIdAsync(addToRoleDTO.UserId);
            if (user == null || !await _RoleManager.RoleExistsAsync(addToRoleDTO.RoleName))
            {
                return " Invalid user ID or Role";
            }

            if (await _userManager.IsInRoleAsync(user, addToRoleDTO.RoleName))
            {
                return "User Already assigned to this role";
            }
            var result = await _userManager.AddToRoleAsync(user, addToRoleDTO.RoleName);

            return result.Succeeded ? "User added to role successfully" : "Failed to add user to role";

        }



        private async Task<JwtSecurityToken> CreateJWTToken(ApplicationUser user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim (ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim (ClaimTypes.NameIdentifier,user.Id),
                new Claim (ClaimTypes.Name,user.UserName?? string.Empty),
                new Claim("FullName", user.FullName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SecretKey));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                claims: claims,
                issuer: _jwt.IssuerIP,
                audience: _jwt.AudienceIP,
                expires: DateTime.UtcNow.AddDays(_jwt.DurationDays),
                signingCredentials: signingCredentials
            );
            return token;
        }

     
    }
}
