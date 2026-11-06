// OpenGDS Auditor reference run: a pull-managed OPC UA client built on the
// OPC Foundation .NET GDS client library (Opc.Ua.Gds.Client.Common), used as
// the trigger hook of `gdsaudit client` (docs/auditor/client-profile.md).
// TEST TARGET, NOT A PRODUCT.
//
// One run is one pull cycle (OPC 10000-12 §7.6, Annex G.1):
//   connect (UserName while the certificate is self-signed, else Anonymous
//   as ApplicationSelfAdmin) -> FindApplications / RegisterApplication ->
//   a pending request first -> GetCertificateStatus -> StartSigningRequest
//   (CSR from our own key) -> FinishRequest (3 polls, 1 s apart) ->
//   GetTrustList -> read the list when LastUpdateTime changed.
// GDSAUDIT_ACTION=probe connects to GDSAUDIT_PROBE_URL; restart is a no-op
// (nothing is kept in memory); run (own schedule) is not supported.
// SPDX-License-Identifier: MPL-2.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Client;
using Opc.Ua.Security.Certificates;

namespace OpenGds.Auditor.Reference
{
    public static class Program
    {
        private const string AppUri = "urn:opengds:test:dotnetpullclient";
        private const string AppName = "OpenGDS Auditor .NET pull client";
        private const int MaxPolls = 3;

        private static string s_dir;
        private static ITelemetryContext s_telemetry;

        public static async Task<int> Main()
        {
            s_dir = Environment.GetEnvironmentVariable("GDSAUDIT_CLIENT_DIR");
            string gdsUrl = Environment.GetEnvironmentVariable("GDSAUDIT_GDS_URL");
            if (string.IsNullOrEmpty(s_dir) || string.IsNullOrEmpty(gdsUrl))
            {
                Console.Error.WriteLine("run me as the trigger of gdsaudit client (GDSAUDIT_* unset)");
                return 2;
            }
            s_telemetry = DefaultTelemetry.Create(b => b.SetMinimumLevel(LogLevel.Warning));
            string action = Environment.GetEnvironmentVariable("GDSAUDIT_ACTION");
            try
            {
                switch (action)
                {
                    case null:
                    case "":
                        return await CycleAsync(gdsUrl).ConfigureAwait(false);
                    case "probe":
                        return await ProbeAsync(Environment.GetEnvironmentVariable("GDSAUDIT_PROBE_URL"))
                            .ConfigureAwait(false);
                    case "restart":
                        Console.WriteLine("restart: nothing is kept in memory between runs");
                        return 0;
                    default:
                        Console.Error.WriteLine($"action {action} is not supported");
                        return 2;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"failed: {e.GetType().Name}: {e.Message}");
                Console.Error.WriteLine(e.StackTrace?.Split('\n').FirstOrDefault(l => l.Contains("Program", StringComparison.Ordinal)));
                return 1;
            }
        }

        private static string Pki => Path.Combine(s_dir, "pki");
        private static string StateFile(string name) => Path.Combine(s_dir, name);

        private static async Task<(ApplicationInstance, ApplicationConfiguration)> ConfigureAsync()
        {
            var own = new CertificateIdentifier
            {
                StoreType = CertificateStoreType.Directory,
                StorePath = Path.Combine(Pki, "own"),
                SubjectName = "CN=" + AppName + ", DC=localhost",
                CertificateType = Opc.Ua.ObjectTypeIds.RsaSha256ApplicationCertificateType
            };
            string tp = StateFile("own-thumbprint");
            if (File.Exists(tp))
            {
                own.Thumbprint = File.ReadAllText(tp).Trim();
            }
            var app = new ApplicationInstance(s_telemetry)
            {
                ApplicationName = AppName,
                ApplicationType = ApplicationType.Client
            };
            ApplicationConfiguration config = await app
                .Build(AppUri, "urn:opengds:test")
                .AsClient()
                .AddSecurityConfiguration(new CertificateIdentifierCollection { own }, Pki)
                .SetAutoAcceptUntrustedCertificates(false)
                .SetRejectUnknownRevocationStatus(false)
                .CreateAsync()
                .ConfigureAwait(false);
            config.SecurityConfiguration.SendCertificateChain = true;
            // give up a call the GDS does not answer (CLI-FLT-07)
            config.TransportQuotas.OperationTimeout = 30000;
            if (!await app.CheckApplicationInstanceCertificatesAsync(true).ConfigureAwait(false))
            {
                throw new InvalidOperationException("no application certificate");
            }
            return (app, config);
        }

        private static async Task<X509Certificate2> OwnAsync(ApplicationConfiguration config)
        {
            CertificateIdentifier id = config.SecurityConfiguration.ApplicationCertificates[0];
            X509Certificate2 c = await id.FindAsync(true).ConfigureAwait(false);
            return c ?? throw new InvalidOperationException("own certificate not found");
        }

        /// The GDS issuer, trusted explicitly (never on first use)
        private static void Bootstrap()
        {
            string mark = StateFile("bootstrapped");
            if (File.Exists(mark))
            {
                return;
            }
            string ca = Environment.GetEnvironmentVariable("GDSAUDIT_GDS_CA");
            string crl = Environment.GetEnvironmentVariable("GDSAUDIT_GDS_CRL");
            Directory.CreateDirectory(Path.Combine(Pki, "trusted", "certs"));
            Directory.CreateDirectory(Path.Combine(Pki, "trusted", "crl"));
            File.Copy(ca, Path.Combine(Pki, "trusted", "certs", "gds-ca.der"), true);
            if (!string.IsNullOrEmpty(crl) && File.Exists(crl))
            {
                File.Copy(crl, Path.Combine(Pki, "trusted", "crl", "gds-ca.crl"), true);
            }
            File.WriteAllText(mark, "1");
        }

        private static async Task<EndpointDescription> SelectEndpointAsync(
            ApplicationConfiguration config, string url)
        {
            var ec = EndpointConfiguration.Create(config);
            using DiscoveryClient dc = await DiscoveryClient.CreateAsync(
                new Uri(url), ec, s_telemetry).ConfigureAwait(false);
            EndpointDescriptionCollection eps = await dc.GetEndpointsAsync(null).ConfigureAwait(false);
            await dc.CloseAsync().ConfigureAwait(false);
            EndpointDescription best = eps
                .Where(e => e.SecurityMode == MessageSecurityMode.SignAndEncrypt &&
                    e.SecurityPolicyUri != SecurityPolicies.Basic256 &&
                    e.SecurityPolicyUri != SecurityPolicies.Basic128Rsa15)
                .OrderByDescending(e => e.SecurityLevel)
                .FirstOrDefault();
            return best ?? throw new InvalidOperationException("no SignAndEncrypt endpoint");
        }

        private static IUserIdentity Credentials()
        {
            string user = Environment.GetEnvironmentVariable("GDSAUDIT_PROMPT_USER");
            string pwf = Environment.GetEnvironmentVariable("GDSAUDIT_PROMPT_PASSWORD_FILE");
            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pwf))
            {
                user = Environment.GetEnvironmentVariable("GDSAUDIT_GDS_USER");
                pwf = Environment.GetEnvironmentVariable("GDSAUDIT_GDS_PASSWORD_FILE");
            }
            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pwf))
            {
                return null;
            }
            string pw = File.ReadAllText(pwf).TrimEnd('\r', '\n');
            return new UserIdentity(user, Encoding.UTF8.GetBytes(pw));
        }

        private static async Task<GlobalDiscoveryServerClient> ConnectAsync(
            ApplicationConfiguration config, string url, bool selfSigned)
        {
            EndpointDescription ep = await SelectEndpointAsync(config, url).ConfigureAwait(false);
            IUserIdentity creds = Credentials();
            // Annex G.1: with a certificate from the GDS the client is its own
            // ApplicationSelfAdmin (Anonymous); credentials for the first one,
            // or when the GDS refuses Anonymous
            IUserIdentity first = selfSigned ? creds : null;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var gds = new GlobalDiscoveryServerClient(config)
                {
                    Endpoint = new ConfiguredEndpoint(null, ep, EndpointConfiguration.Create(config))
                };
                // after Endpoint: setting a new endpoint clears AdminCredentials
                gds.AdminCredentials = first;
                try
                {
                    await gds.ConnectAsync().ConfigureAwait(false);
                    Console.WriteLine($"connected to {url} ({ep.SecurityPolicyUri}, " +
                        $"{(first == null ? "Anonymous" : "UserName")})");
                    return gds;
                }
                catch (ServiceResultException e) when (first == null && creds != null &&
                    (e.StatusCode == StatusCodes.BadIdentityTokenRejected ||
                     e.StatusCode == StatusCodes.BadIdentityTokenInvalid ||
                     e.StatusCode == StatusCodes.BadUserAccessDenied))
                {
                    Console.WriteLine($"Anonymous refused ({StatusCodes.GetBrowseName(e.StatusCode)}): user credentials");
                    gds.Dispose();
                    first = creds;
                }
            }
            throw new InvalidOperationException("could not connect to the GDS");
        }

        private static async Task<NodeId> ApplicationIdAsync(GlobalDiscoveryServerClient gds)
        {
            ApplicationRecordDataType[] found = await gds.FindApplicationAsync(AppUri).ConfigureAwait(false);
            if (found != null && found.Length > 0)
            {
                return found[0].ApplicationId;
            }
            var rec = new ApplicationRecordDataType
            {
                ApplicationUri = AppUri,
                ApplicationType = ApplicationType.Client,
                ApplicationNames = new LocalizedTextCollection { new LocalizedText("en", AppName) },
                ProductUri = "urn:opengds:test"
            };
            NodeId id = await gds.RegisterApplicationAsync(rec).ConfigureAwait(false);
            Console.WriteLine($"registered as {id}");
            return id;
        }

        private static async Task<int> CycleAsync(string url)
        {
            Bootstrap();
            (ApplicationInstance _, ApplicationConfiguration config) = await ConfigureAsync().ConfigureAwait(false);
            X509Certificate2 own = await OwnAsync(config).ConfigureAwait(false);
            bool selfSigned = X509Utils.IsSelfSigned(own);
            using GlobalDiscoveryServerClient gds = await ConnectAsync(config, url, selfSigned).ConfigureAwait(false);
            try
            {
                NodeId appId = await ApplicationIdAsync(gds).ConfigureAwait(false);
                NodeId group = ExpandedNodeId.ToNodeId(
                    Opc.Ua.Gds.ObjectIds.Directory_CertificateGroups_DefaultApplicationGroup, gds.Session.NamespaceUris);
                NodeId type = Opc.Ua.ObjectTypeIds.RsaSha256ApplicationCertificateType;

                // 12 §7.6: a request still pending from an earlier cycle comes first
                NodeId requestId = LoadPending();
                if (requestId == null)
                {
                    bool update = selfSigned || await gds.GetCertificateStatusAsync(appId, group, type)
                        .ConfigureAwait(false);
                    Console.WriteLine($"update required: {update}");
                    if (update)
                    {
                        // 12 §7.6: a new key for each request; it stays with the
                        // pending request until the certificate is issued
                        using X509Certificate2 keyHolder = CertificateFactory
                            .CreateCertificate(AppUri, AppName, own.Subject, new List<string> { "localhost" })
                            .SetRSAKeySize(2048)
                            .CreateForRSA();
                        byte[] csr = CertificateFactory.CreateSigningRequest(keyHolder, new List<string> { "localhost" });
                        requestId = await gds.StartSigningRequestAsync(appId, group, type, csr)
                            .ConfigureAwait(false);
                        SavePending(requestId, keyHolder);
                    }
                }
                else
                {
                    Console.WriteLine("resuming the pending request");
                }
                if (requestId != null)
                {
                    await FinishAsync(gds, config, own, appId, requestId).ConfigureAwait(false);
                }
                await TrustListAsync(gds, config, appId, group).ConfigureAwait(false);
            }
            finally
            {
                await gds.DisconnectAsync().ConfigureAwait(false);
            }
            return 0;
        }

        private static NodeId LoadPending()
        {
            string f = StateFile("pending-request-id");
            return File.Exists(f) ? NodeId.Parse(File.ReadAllText(f).Trim()) : null;
        }

        private static void SavePending(NodeId id, X509Certificate2 keyHolder)
        {
            if (id != null)
            {
                // key first: an id without its key is useless
                File.WriteAllBytes(StateFile("pending-key.pfx"), keyHolder.Export(X509ContentType.Pfx));
                File.WriteAllText(StateFile("pending-request-id"), id.ToString());
            }
        }

        private static X509Certificate2 PendingKey(X509Certificate2 own)
        {
            string f = StateFile("pending-key.pfx");
            return File.Exists(f)
                ? X509CertificateLoader.LoadPkcs12FromFile(f, null, X509KeyStorageFlags.Exportable)
                : own;
        }

        private static void ClearPending()
        {
            File.Delete(StateFile("pending-request-id"));
            File.Delete(StateFile("pending-key.pfx"));
        }

        private static async Task FinishAsync(GlobalDiscoveryServerClient gds, ApplicationConfiguration config,
            X509Certificate2 own, NodeId appId, NodeId requestId)
        {
            for (int poll = 0; poll < MaxPolls; poll++)
            {
                if (poll > 0)
                {
                    await Task.Delay(1000).ConfigureAwait(false);
                }
                byte[] cert;
                byte[][] issuers;
                try
                {
                    (cert, _, issuers) = await gds.FinishRequestAsync(appId, requestId).ConfigureAwait(false);
                }
                catch (ServiceResultException e) when (e.StatusCode == StatusCodes.BadNothingToDo)
                {
                    Console.WriteLine("pending approval");
                    continue;
                }
                catch (ServiceResultException e)
                {
                    Console.WriteLine($"FinishRequest: {StatusCodes.GetBrowseName(e.StatusCode)}; request dropped");
                    ClearPending();
                    return;
                }
                X509Certificate2 keyHolder = PendingKey(own);
                ClearPending();
                if (cert != null)
                {
                    await InstallAsync(config, own, keyHolder, cert, issuers ?? Array.Empty<byte[]>())
                        .ConfigureAwait(false);
                }
                return;
            }
            Console.WriteLine("still pending: resumed in the next cycle");
        }

        /// Install only a certificate for our key and ApplicationUri, valid
        /// now and chained to a CA we trust (4 §6.1.3)
        private static async Task InstallAsync(ApplicationConfiguration config, X509Certificate2 own,
            X509Certificate2 keyHolder, byte[] der, byte[][] issuers)
        {
            using X509Certificate2 issued = X509CertificateLoader.LoadCertificate(der);
            using RSA ownKey = keyHolder.GetRSAPrivateKey();
            using RSA newPub = issued.GetRSAPublicKey();
            if (ownKey == null || newPub == null ||
                !ownKey.ExportParameters(false).Modulus.SequenceEqual(newPub.ExportParameters(false).Modulus))
            {
                Console.WriteLine("issued certificate is for another key - refused");
                return;
            }
            if (X509Utils.GetApplicationUrisFromCertificate(issued).All(u => u != AppUri))
            {
                Console.WriteLine("issued certificate names another ApplicationUri - refused");
                return;
            }
            if (issued.NotBefore > DateTime.Now || issued.NotAfter < DateTime.Now)
            {
                Console.WriteLine("issued certificate is not valid now - refused");
                return;
            }
            var issuerCerts = issuers.Select(b => X509CertificateLoader.LoadCertificate(b)).ToList();
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                using ICertificateStore trusted = config.SecurityConfiguration.TrustedPeerCertificates
                    .OpenStore(s_telemetry);
                foreach (X509Certificate2 t in await trusted.EnumerateAsync().ConfigureAwait(false))
                {
                    chain.ChainPolicy.CustomTrustStore.Add(t);
                }
                foreach (X509Certificate2 i in issuerCerts)
                {
                    chain.ChainPolicy.ExtraStore.Add(i);
                }
                if (!chain.Build(issued))
                {
                    Console.WriteLine("issued certificate is not from a trusted CA - refused");
                    return;
                }
            }
            using ICertificateStore ownStore = config.SecurityConfiguration.ApplicationCertificates[0]
                .OpenStore(s_telemetry);
            X509Certificate2 withKey = issued.CopyWithPrivateKey(ownKey);
            await ownStore.AddAsync(withKey).ConfigureAwait(false);
            if (!string.Equals(own.Thumbprint, withKey.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                await ownStore.DeleteAsync(own.Thumbprint).ConfigureAwait(false);
            }
            File.WriteAllText(StateFile("own-thumbprint"), withKey.Thumbprint);
            using ICertificateStore issuerStore = config.SecurityConfiguration.TrustedIssuerCertificates
                .OpenStore(s_telemetry);
            foreach (X509Certificate2 i in issuerCerts)
            {
                if ((await issuerStore.FindByThumbprintAsync(i.Thumbprint).ConfigureAwait(false)).Count == 0)
                {
                    await issuerStore.AddAsync(i).ConfigureAwait(false);
                }
            }
            Console.WriteLine($"installed {withKey.Subject} ({withKey.Thumbprint}) + {issuerCerts.Count} issuer(s)");
        }

        private static async Task<DateTime?> LastUpdateTimeAsync(ISession session, NodeId tlId)
        {
            var paths = new BrowsePathCollection
            {
                new BrowsePath
                {
                    StartingNode = tlId,
                    RelativePath = new RelativePath(new QualifiedName("LastUpdateTime"))
                }
            };
            TranslateBrowsePathsToNodeIdsResponse r = await session
                .TranslateBrowsePathsToNodeIdsAsync(null, paths, CancellationToken.None).ConfigureAwait(false);
            if (r.Results.Count != 1 || StatusCode.IsBad(r.Results[0].StatusCode) || r.Results[0].Targets.Count == 0)
            {
                return null;
            }
            var id = ExpandedNodeId.ToNodeId(r.Results[0].Targets[0].TargetId, session.NamespaceUris);
            DataValue v = await session.ReadValueAsync(id).ConfigureAwait(false);
            return v.Value is DateTime t ? t : null;
        }

        /// 12 §7.6, §7.8.2.8: the list replaces the stores; download only when
        /// LastUpdateTime changed
        private static async Task TrustListAsync(GlobalDiscoveryServerClient gds, ApplicationConfiguration config,
            NodeId appId, NodeId group)
        {
            NodeId tlId = await gds.GetTrustListAsync(appId, group).ConfigureAwait(false);
            DateTime? updated = await LastUpdateTimeAsync(gds.Session, tlId).ConfigureAwait(false);
            string mark = StateFile("trustlist-updated");
            if (updated.HasValue && File.Exists(mark) &&
                File.ReadAllText(mark).Trim() == updated.Value.Ticks.ToString())
            {
                Console.WriteLine("trust list unchanged since the last download: skipped");
                return;
            }
            TrustListDataType tl = await gds.ReadTrustListAsync(tlId).ConfigureAwait(false);
            var mask = (TrustListMasks)tl.SpecifiedLists;
            if ((mask & TrustListMasks.TrustedCertificates) != 0 || (mask & TrustListMasks.TrustedCrls) != 0)
            {
                await ReplaceAsync(config.SecurityConfiguration.TrustedPeerCertificates,
                    tl.TrustedCertificates, tl.TrustedCrls).ConfigureAwait(false);
            }
            if ((mask & TrustListMasks.IssuerCertificates) != 0 || (mask & TrustListMasks.IssuerCrls) != 0)
            {
                await ReplaceAsync(config.SecurityConfiguration.TrustedIssuerCertificates,
                    tl.IssuerCertificates, tl.IssuerCrls).ConfigureAwait(false);
            }
            if (updated.HasValue)
            {
                File.WriteAllText(mark, updated.Value.Ticks.ToString());
            }
            Console.WriteLine($"trust list installed: {tl.TrustedCertificates.Count} trusted, " +
                $"{tl.TrustedCrls.Count} CRLs, {tl.IssuerCertificates.Count} issuers");
        }

        private static async Task ReplaceAsync(CertificateTrustList list, ByteStringCollection certs,
            ByteStringCollection crls)
        {
            // parse everything first: a bad list leaves the old one in use
            var parsedCerts = certs.Select(b => X509CertificateLoader.LoadCertificate(b)).ToList();
            var parsedCrls = crls.Select(b => new X509CRL(b)).ToList();
            using ICertificateStore store = list.OpenStore(s_telemetry);
            foreach (X509Certificate2 c in await store.EnumerateAsync().ConfigureAwait(false))
            {
                await store.DeleteAsync(c.Thumbprint).ConfigureAwait(false);
            }
            foreach (X509CRL c in await store.EnumerateCRLsAsync().ConfigureAwait(false))
            {
                await store.DeleteCRLAsync(c).ConfigureAwait(false);
            }
            foreach (X509Certificate2 c in parsedCerts)
            {
                await store.AddAsync(c).ConfigureAwait(false);
            }
            foreach (X509CRL c in parsedCrls)
            {
                await store.AddCRLAsync(c).ConfigureAwait(false);
            }
        }

        /// Connect to the probe server with what is installed now; exit 0 when
        /// a session was activated
        private static async Task<int> ProbeAsync(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return 2;
            }
            (ApplicationInstance _, ApplicationConfiguration config) = await ConfigureAsync().ConfigureAwait(false);
            EndpointDescription ep = await SelectEndpointAsync(config, url).ConfigureAwait(false);
            var endpoint = new ConfiguredEndpoint(null, ep, EndpointConfiguration.Create(config));
            var factory = new DefaultSessionFactory(s_telemetry);
            using ISession session = await factory.CreateAsync(config, endpoint, false, false,
                AppName, 30000, new UserIdentity(), null, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"probe: connected to {url}");
            await session.CloseAsync().ConfigureAwait(false);
            return 0;
        }
    }
}
