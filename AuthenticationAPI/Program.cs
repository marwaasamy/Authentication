
using AuthenticationAPI.Data;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthenticationAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("cs"));
            });
            builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
            builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));


            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IEmailSender, EmailSender>();
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>(
               options =>
               {
                   // Configure password requirements
                   options.Password.RequireUppercase = true; // Requires at least one uppercase letter
                   options.Password.RequireLowercase = true;
                   options.Password.RequireDigit = true;
                   options.Password.RequireNonAlphanumeric = true;
                   options.Password.RequiredLength = 8;
                   options.SignIn.RequireConfirmedEmail = true; // Require email confirmation
                   options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
               })
              .AddEntityFrameworkStores<ApplicationDbContext>()
              .AddDefaultTokenProviders();

            builder.Services.AddAuthentication(options => //how to validate
            {
                options.DefaultAuthenticateScheme =
                JwtBearerDefaults.AuthenticationScheme;//not cookie
                options.DefaultChallengeScheme =//if you aren't valid or have token
                JwtBearerDefaults.AuthenticationScheme; //unauthorized
                options.DefaultScheme =
                JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options => //how to verify
            {
                var jwtOptions = builder.Configuration.GetSection("JWT").Get<JWT>();

                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters =
                new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.IssuerIP,
                    ValidateAudience = true,
                    ValidAudience = jwtOptions.AudienceIP,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey =
                     new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                               jwtOptions.SecretKey))
                };
            });
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
                app.UseSwaggerUI(options => options.SwaggerEndpoint("/openapi/v1.json", "v1"));
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
