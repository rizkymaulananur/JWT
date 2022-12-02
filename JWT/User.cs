namespace JWT
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswwordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
