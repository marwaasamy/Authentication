using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationAPI.Helpers
{
    public class JWT
    {
        public string SecretKey { get; set; }
        public string AudienceIP { get; set; }
        public string IssuerIP { get; set; }

        public double DurationDays { get; set; }
    }
}
