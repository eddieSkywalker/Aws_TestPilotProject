using System.Collections.Concurrent;

namespace CompanyPortal.Services
{
    public interface ITokenService
    {
        Task StoreTokenAsync(string sessionId, string accessToken, string? idToken = null);
        Task<string?> GetAccessTokenAsync(string sessionId);
        Task<string?> GetIdTokenAsync(string sessionId);
        Task ClearTokensAsync(string sessionId);
    }

    public class TokenService : ITokenService
    {
        private readonly ConcurrentDictionary<string, TokenData> _tokens = new();

        public Task StoreTokenAsync(string sessionId, string accessToken, string? idToken = null)
        {
            _tokens.AddOrUpdate(sessionId, new TokenData(accessToken, idToken), 
                (key, existing) => new TokenData(accessToken, idToken));
            return Task.CompletedTask;
        }

        public Task<string?> GetAccessTokenAsync(string sessionId)
        {
            return Task.FromResult(_tokens.TryGetValue(sessionId, out var tokenData) ? tokenData.AccessToken : null);
        }

        public Task<string?> GetIdTokenAsync(string sessionId)
        {
            return Task.FromResult(_tokens.TryGetValue(sessionId, out var tokenData) ? tokenData.IdToken : null);
        }

        public Task ClearTokensAsync(string sessionId)
        {
            _tokens.TryRemove(sessionId, out _);
            return Task.CompletedTask;
        }

        private record TokenData(string AccessToken, string? IdToken);
    }
}
