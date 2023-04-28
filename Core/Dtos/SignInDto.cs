using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthServer.Core.Dtos
{
    public class SignInDto
    {
        public string EMail { get; set; }
        public string Password { get; set; }
    }
}
