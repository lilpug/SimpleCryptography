using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SimpleCryptography.Business.AuthenticationServices;
using SimpleCryptography.Business.EncryptionServices;
using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Business.StartupConfiguration
{
    public static class ServicesConfiguration
    {
        public static void AddAesCbcService(this IServiceCollection services)
        {
            services.TryAddScoped(typeof(IEncryptionService), serviceProvider => new AesCbcService());
        }
        
        public static void AddAesGcmService(this IServiceCollection services)
        {
            services.TryAddScoped(typeof(IEncryptionService), serviceProvider => new AesGcmService());
        }
        
        public static void AddRsaService(this IServiceCollection services)
        {
            services.TryAddScoped(typeof(IEncryptionService), serviceProvider => new RsaService());
        }
        
        public static void AddHmac256Service(this IServiceCollection services)
        {
            services.TryAddScoped(typeof(IMessageAuthenticationService), serviceProvider => new HmacSha256Service());
        }
        
        public static void AddHmac512Service(this IServiceCollection services)
        {
            services.TryAddScoped(typeof(IMessageAuthenticationService), serviceProvider => new HmacSha512Service());
        }
    }
}