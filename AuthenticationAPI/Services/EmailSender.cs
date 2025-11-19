using AuthenticationAPI.Helpers;
using AuthenticationAPI.Services.Interfaces;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Utils;

namespace AuthenticationAPI.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly EmailSettings _emailSettings;

        public EmailSender(IConfiguration configuration, IOptions<EmailSettings> emailSettings)
        {
            _configuration = configuration;
            _emailSettings = emailSettings.Value;
        }

        public async Task SendEmailAsync(string email, string subject, string body)
        {
            var EmailMessage = new MimeMessage
            {
                Sender = MailboxAddress.Parse(_emailSettings.Email),
                MessageId = MimeUtils.GenerateMessageId() // Ensure each email has a unique ID
            };

            EmailMessage.From.Add(new MailboxAddress(_emailSettings.DisplayName, _emailSettings.Email));
            EmailMessage.To.Add(MailboxAddress.Parse(email));
            EmailMessage.Subject = subject;
            var builder = new BodyBuilder
            {
                HtmlBody = body
            };
            EmailMessage.Body = builder.ToMessageBody();

            using var smtp = new MailKit.Net.Smtp.SmtpClient();
            await smtp.ConnectAsync(_emailSettings.Host, _emailSettings.Port, SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(_emailSettings.Email, _emailSettings.Password);
            await smtp.SendAsync(EmailMessage);
            await smtp.DisconnectAsync(true);


        }
    }
}
