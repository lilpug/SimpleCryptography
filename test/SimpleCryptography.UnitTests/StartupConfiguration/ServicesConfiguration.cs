using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using SimpleCryptography.Business.AuthenticationServices;
using SimpleCryptography.Business.EncryptionServices;
using SimpleCryptography.Business.StartupConfiguration;
using SimpleCryptography.Data.Interfaces;
using Xunit;

namespace SimpleCryptography.UnitTests.StartupConfiguration
{
    public class ServicesConfigurationTests
    {
        private ServiceCollection ServiceCollection { get; set; }
        
        public ServicesConfigurationTests()
        {
            ServiceCollection = new ServiceCollection();
        }
        
        [Fact]
        public void AddAesCbcService()
        {   
            Assert.DoesNotContain(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));
            ServiceCollection.AddAesCbcService();
            Assert.Contains(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));

            IServiceProvider provider = ServiceCollection.BuildServiceProvider();
            var service = provider.GetRequiredService(typeof(IEncryptionService));
            
            Assert.Equal(typeof(AesCbcService), service?.GetType());
        }
        
        [Fact]
        public void AddAesGcmService()
        {   
            Assert.DoesNotContain(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));
            ServiceCollection.AddAesGcmService();
            Assert.Contains(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));

            IServiceProvider provider = ServiceCollection.BuildServiceProvider();
            var service = provider.GetRequiredService(typeof(IEncryptionService));
            
            Assert.Equal(typeof(AesGcmService), service?.GetType());
        }
        
        [Fact]
        public void AddRsaService()
        {   
            Assert.DoesNotContain(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));
            ServiceCollection.AddRsaService();
            Assert.Contains(ServiceCollection, x => x.ServiceType == typeof(IEncryptionService));

            IServiceProvider provider = ServiceCollection.BuildServiceProvider();
            var service = provider.GetRequiredService(typeof(IEncryptionService));
            
            Assert.Equal(typeof(RsaService), service?.GetType());
        }
        
        [Fact]
        public void AddHmac256Service()
        {   
            Assert.DoesNotContain(ServiceCollection, x => x.ServiceType == typeof(IMessageAuthenticationService));
            ServiceCollection.AddHmac256Service();
            Assert.Contains(ServiceCollection, x => x.ServiceType == typeof(IMessageAuthenticationService));

            IServiceProvider provider = ServiceCollection.BuildServiceProvider();
            var service = provider.GetRequiredService(typeof(IMessageAuthenticationService));
            
            Assert.Equal(typeof(HmacSha256Service), service?.GetType());
        }
        
        [Fact]
        public void AddHmac512Service()
        {   
            Assert.DoesNotContain(ServiceCollection, x => x.ServiceType == typeof(IMessageAuthenticationService));
            ServiceCollection.AddHmac512Service();
            Assert.Contains(ServiceCollection, x => x.ServiceType == typeof(IMessageAuthenticationService));

            IServiceProvider provider = ServiceCollection.BuildServiceProvider();
            var service = provider.GetRequiredService(typeof(IMessageAuthenticationService));
            
            Assert.Equal(typeof(HmacSha512Service), service?.GetType());
        }
    }
}