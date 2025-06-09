namespace JwtAuth.Models
{
    public class TokenResponseDto
    {
        public required string AccessToken { get; set; }
        public required string RefershToken { get; set; }
    }
}
