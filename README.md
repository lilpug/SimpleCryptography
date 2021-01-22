# SimpleCryptography

SimpleCryptography is a library designed to make using encryption and message authentication services nice and simple.

[![NuGet](https://img.shields.io/nuget/v/SimpleCryptography.svg?maxAge=3600)](https://www.nuget.org/packages/SimpleCryptography/1.0.0)

## Getting Started

1. Install the library via its NuGet package.

2. Create the class required or use Dependency Injection.

3. Use the service.

## Dependency Injection

You can either use the 'IMessageAuthenticationService' or 'IEncryptionService' interfaces to manually add the services into a dependency injection system.

Alternatively, you can use the built in Service collection extension functions to register one of the encryption and message authentication services into .NET directly.

### Service extension functions

```C#
services.AddAesCbcService();
services.AddAesGcmService();
services.AddRsaService();
services.AddHmac256Service();
services.AddHmac512Service();
```

### Dependency injection usage example
```c#
public class ExampleController : Controller
{
	private readonly IEncryptionService _encryptionService;
	private readonly IMessageAuthenticationService _messageAuthenticationService;
	
	public ExampleController(IEncryptionService encryptionService, IMessageAuthenticationService messageAuthenticationService)
	{
		_encryptionService = encryptionService;
		_messageAuthenticationService = messageAuthenticationService;
	}
}

```

## Encryption Services

This library supports three main encryption services, AES-CBC, AES-GCM and RSA.

All of these encryption services have the same underlining functions to encrypt and decrypt data.

### AES CBC and AES GCM

The AES-CBC and AES-GCM services can be created by using either the 'AesCbcService' or 'AesGcmService' class.

#### AES-CBC Service Creation

```C#	
IEncryptionService aesCbcService = new AesCbcService();	
```

#### AES-GCM Service Creation
```C#		
IEncryptionService aesGcmService = new AesGcmService();
```

### RSA

The RSA service can be created by using the 'RsaService' class.

#### RSA Service Creation

```C#	
IEncryptionService rsaService = new RsaService();	
```

### Example usages of the shared encryption and decryption functions

**Note: When data is returned in string format from the encrypted functions, it is a base64 string.**

```C#
List<string> data = new List<string>() {"abc", "abc2"};

//bytes example
var bytesEncrypted = encryptionService.EncryptToBytes(key, data);
var bytesDecrypted = encryptionService.DecryptToType<List<string>>(key, bytesEncrypted);

//string example
var stringEncrypted = encryptionService.EncryptToString(key, data);
var stringDecrypted = encryptionService.DecryptToType<List<string>>(key, stringEncrypted);
```

## Message Authentication Services

### HMAC Services

There are two main HMAC supported services, these can be created using the either of the 'HmacSha256Service' or 'HmacSha512Service' classes.

Both services share the same underlining functionality except their tag sizes.

**Note: When suppying the data from string format on any of the functions, it must be in a base64 format.**

### HMACSHA256 Service Creation

```C#	
IMessageAuthenticationService hmacService = new HmacSha256Service();
```

### HMACSHA512 Service Creation

```C#		
IMessageAuthenticationService hmacService = new HmacSha512Service();
```


### Example usages of the shared signing and verifying functions

```C#
string key = "random test key";
byte[] data = new byte[] {123, 123, 123, 123, 123};

//If your supplying the data from string format, it must be from a base64 string!
string dataString = Convert.ToBase64String(data);

//Standard bytes example
var bytesSignedData = hmacService.SignDataToBytes(key, data);
var bytesVerifiedData = hmacService.VerifyDataToBytes(key, bytesSignedData);

//Standard string example
var stringSignedData = hmacService.SignDataToString(key, data);
var stringVerifiedData = hmacService.VerifyDataToString(key, stringSignedData);

//With expiration bytes example
var expBytesSignedData = hmacService.SignDataToBytes(key, data, TimeSpan.FromSeconds(30));
var expBytesVerifiedData = hmacService.VerifyDataToBytes(key, expBytesSignedData, true);

//With expiration string example
var expStringSignedData = hmacService.SignDataToString(key, data, TimeSpan.FromSeconds(30));
var expStringVerifiedData = hmacService.VerifyDataToString(key, expStringSignedData, true);
```