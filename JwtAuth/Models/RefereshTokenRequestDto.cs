namespace JwtAuth.Models
{
    public class RefereshTokenRequestDto
    {
        public required Guid UserId { get; set; }
        public required string RefreshToken { get; set; }
    }
}
