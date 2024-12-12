using System;
using System.Threading.Tasks;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;

namespace AwsSignatureVersion4.Private
{
    /// <summary>
    /// Class wrapping an instance of <see cref="ImmutableCredentials"/> into an
    /// <see cref="AWSCredentials"/>.
    /// </summary>
    public class AWSCredentialsWrapper : AWSCredentials
    {
#if NET5_0_OR_GREATER
        [MemberNotNullWhen(true, nameof(credentials))]
#endif
        private readonly ImmutableCredentials? credentials;
#if NET5_0_OR_GREATER
        [MemberNotNullWhen(true, nameof(securityTokenService), nameof(roleArn), nameof(roleSessionName))]
#endif
        private readonly IAmazonSecurityTokenService? securityTokenService;
#if NET5_0_OR_GREATER
        [MemberNotNullWhen(true, nameof(securityTokenService), nameof(roleArn), nameof(roleSessionName))]
#endif
        private readonly string? roleArn;
#if NET5_0_OR_GREATER
        [MemberNotNullWhen(true, nameof(securityTokenService), nameof(roleArn), nameof(roleSessionName))]
#endif
        private readonly string? roleSessionName;

        public AWSCredentialsWrapper(ImmutableCredentials credentials)
        {
            this.credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        }

        public AWSCredentialsWrapper(IAmazonSecurityTokenService securityTokenService, string roleArn, string roleSessionName)
        {
            this.securityTokenService = securityTokenService ?? throw new ArgumentNullException(nameof(securityTokenService));
            this.roleArn = roleArn ?? throw new ArgumentNullException(nameof(roleArn));
            this.roleSessionName = roleSessionName ?? throw new ArgumentNullException(nameof(roleSessionName));
        }

        private async Task<ImmutableCredentials> GetAssumedRoleCredentials()
        {
            if (securityTokenService is not null && !string.IsNullOrEmpty(roleArn) && !string.IsNullOrEmpty(roleSessionName))
            {
                var assumeRoleRequest = new AssumeRoleRequest
                {
                    RoleArn = roleArn,
                    RoleSessionName = roleSessionName
                };

                var assumeRoleResponse = await securityTokenService
                    .AssumeRoleAsync(assumeRoleRequest)
                    .ConfigureAwait(false);

                return new ImmutableCredentials(
                    assumeRoleResponse.Credentials.AccessKeyId,
                    assumeRoleResponse.Credentials.SecretAccessKey,
                    assumeRoleResponse.Credentials.SessionToken);
            }

            throw new InvalidOperationException("Cannot assume role without STS client, role ARN, and role session name.");
        }

        public override ImmutableCredentials GetCredentials()
        {
            if (credentials is not null)
            {
                return credentials;
            }

            return GetAssumedRoleCredentials().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public override async Task<ImmutableCredentials> GetCredentialsAsync()
        {
            if (credentials is not null)
            {
                return await Task.FromResult(credentials);
            }

            return await GetAssumedRoleCredentials();
        }
    }
}
