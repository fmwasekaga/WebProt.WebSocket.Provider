#region Using
using CommandLineParser.Arguments;
using CommandLineParser.Exceptions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Logging.io;
using WebSocketSharp.Server;
using WebProt.WebSocket.Provider.Extensions;
using Newtonsoft.Json;
using System.Globalization;
using Plugable.io.Interfaces;
using Plugable.io;
using System.Reflection;
using System.IO.Compression;
#endregion

namespace WebProt.WebSocket.Provider
{
    public class WebExtension : IPlugable, IProtocolProvider
    {
        #region Variables
        private ILog Logger = LogProvider.GetCurrentClassLogger();
        private List<WebSocketServer> nonSecured_ws = new List<WebSocketServer>();
        private List<WebSocketServer> secured_ws = new List<WebSocketServer>();

        //private List<HttpServer> nonSecured_http = new List<HttpServer>();
        //private List<HttpServer> secured_http = new List<HttpServer>();

        private enum SslProtocolsHack
        {
            Tls = 192,
            Tls11 = 768,
            Tls12 = 3072
        }
        #endregion

        #region Initialize
        public void Initialize(string[] args, PluginsManager server)
        {
            if (args.Length > 0)
            {
                AppDomain.CurrentDomain.AssemblyResolve += ResolveAssembly;

                string[] parsedArgs = null;

                try
                {
                    ValueArgument<string> argument = new ValueArgument<string>('p', "wp", "Arguements for this plugin");

                    var _parser = new CommandLineParser.CommandLineParser(args);
                    _parser.Arguments.Add(argument);
                    _parser.ParseCommandLine();

                    parsedArgs = argument.Value.ToArguments();
                }
                catch (CommandLineException e)
                {
                    Extension.Error(e.Message);
                    if (server != null)
                    {
                        server.MessageProvider(getName(), new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture),
                            MessageType = "Error",
                            Message = e.Message
                        });
                    }
                }

                if (parsedArgs != null)
                {
                    var parser = new CommandLineParser.CommandLineParser(parsedArgs);

                    ValueArgument<int> nonSecuredArgument = new ValueArgument<int>('w', "ws", "The web socket port");
                    nonSecuredArgument.AllowMultiple = true;

                    ValueArgument<int> SecuredArgument = new ValueArgument<int>('x', "wss", "The secure web socket port");
                    SecuredArgument.AllowMultiple = true;

                    parser.Arguments.Add(nonSecuredArgument);
                    parser.Arguments.Add(SecuredArgument);

                    try { parser.ParseCommandLine(); }
                    catch (CommandLineException e)
                    {
                        Extension.Error(e.Message);//.ConfigureAwait(false);
                        if (server != null)
                        {
                            server.MessageProvider(getName(), new
                            {
                                Timestamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture),
                                MessageType = "Error",
                                Message = e.Message
                            });
                        }
                        parser.ShowUsage();
                    }

                    if ((nonSecuredArgument != null && nonSecuredArgument.Values.Any()) ||
                        (SecuredArgument != null && SecuredArgument.Values.Any()))
                    {
                        System.Security.Cryptography.X509Certificates.X509Certificate2 serverCertificate = null;

                        var shutdowntimer = new System.Timers.Timer(3000);
                        shutdowntimer.AutoReset = false;
                        shutdowntimer.Elapsed += (s, arg) => { Environment.Exit(0); };

                        ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicy) => { return true; };

                        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                        var plugins = Path.Combine(Environment.CurrentDirectory, "extensions").GetPlugable(getName()).OfType<IProtocolPlugin>().ToList();

                        if (nonSecuredArgument != null)
                        {
                            foreach (var value in nonSecuredArgument.Values)
                            {
                                //Logger.InfoFormat("Setting up (ws) on {0}", value);
                                var srv_ws = new WebSocketServer(IPAddress.Any, value);
                                srv_ws.Plugins(plugins, args, server);
                                nonSecured_ws.Add(srv_ws);

                                /*Logger.InfoFormat("Setting up (http) on {0}", value);
                                var srv_http = new HttpServer(IPAddress.Any, value);
                                srv_http.Plugins(plugins, args, server);
                                nonSecured_http.Add(srv_http);*/
                            }
                        }

                        if (SecuredArgument != null)
                        {
                            foreach (var value in SecuredArgument.Values)
                            {
                                if (serverCertificate == null)
                                    serverCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(Path.Combine("certificates", "server.pfx"), "admin123$");

                                //Logger.InfoFormat("Setting up (wss) on {0}", value);
                                var srv_ws = new WebSocketServer(IPAddress.Any, value, true);
                                srv_ws.SslConfiguration.ServerCertificate = serverCertificate;
                                var sslProtocolHack = (System.Security.Authentication.SslProtocols)(SslProtocolsHack.Tls12 | SslProtocolsHack.Tls11 | SslProtocolsHack.Tls);
                                srv_ws.SslConfiguration.EnabledSslProtocols = sslProtocolHack;
                                srv_ws.Plugins(plugins, args, server);
                                secured_ws.Add(srv_ws);

                                /*Logger.InfoFormat("Setting up (https) on {0}", value);
                                var srv_http = new HttpServer(IPAddress.Any, value, true);
                                srv_http.SslConfiguration.ServerCertificate = serverCertificate;
                                srv_http.Log.Level = WebSocketSharp.LogLevel.Trace;
                                srv_http.Plugins(plugins, args, server);
                                secured_http.Add(srv_http);*/
                            }
                        }

                        server.LogEvent += (s, arg) =>
                        {
                            if (arg.IsError)
                            {
                                server.MessageProvider(getName(), new
                                {
                                    Timestamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture),
                                    MessageType = "Error",
                                    Message = arg.Message
                                });
                            }
                            else
                            {
                                server.MessageProvider(getName(), new
                                {
                                    Timestamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture),
                                    MessageType = "LogEvent",
                                    Message = arg.Message
                                });
                            }
                        };
                    }
                }
            }
            else Logger.InfoFormat(getName() + " not started, missing startup arguments.");
        }
        #endregion

        #region Start
        public void Start()
        {
            var hostName = Dns.GetHostName();
            var hostEntry = Dns.GetHostEntry(hostName);
            var CurrentIP = hostEntry.AddressList.Where(s => s.IsIPv6LinkLocal == false).FirstOrDefault();

            foreach (var srv in nonSecured_ws)
            {
                srv.Start();
                if (srv.IsListening){
                    if (CurrentIP != null) Logger.InfoFormat(getName() + " listening on ws://{0}:{1}, services:", CurrentIP, srv.Port);
                    else Logger.InfoFormat(getName() + " listening on ws://127.0.0.1:{0}, services:", srv.Port);
                    foreach (var path in srv.WebSocketServices.Paths)
                        Logger.InfoFormat("- {0}", path);
                }
            }

            foreach (var srv in secured_ws)
            {
                srv.Start();
                if (srv.IsListening){
                    if (CurrentIP != null) Logger.InfoFormat(getName() + " listening on wss://{0}:{1}, services:", CurrentIP, srv.Port);
                    else Logger.InfoFormat(getName() + " listening on wss://127.0.0.1:{0}, services:", srv.Port);
                    foreach (var path in srv.WebSocketServices.Paths)
                        Logger.InfoFormat("- {0}", path);
                }
            }

            /*foreach (var srv in nonSecured_http)
            {
                srv.Start();
                if (srv.IsListening)
                {
                    Logger.InfoFormat("Listening (http) on port {0}, services:", srv.Port);
                    foreach (var path in srv.WebSocketServices.Paths)
                        Logger.InfoFormat("- {0}", path);
                }
            }

            foreach (var srv in secured_http)
            {
                srv.Start();
                if (srv.IsListening)
                {
                    Logger.InfoFormat("Listening (https) on port {0}, services:", srv.Port);
                    foreach (var path in srv.WebSocketServices.Paths)
                        Logger.InfoFormat("- {0}", path);
                }
            }*/
        }
        #endregion

        #region Stop
        public void Stop()
        {
            foreach (var srv in nonSecured_ws)
            {
                Logger.InfoFormat("Stopping (ws) on {0}", srv.Port);
                srv.Stop();
            }

            foreach (var srv in secured_ws)
            {
                Logger.InfoFormat("Stopping (wss) on {0}", srv.Port);
                srv.Stop();
            }

            /*foreach (var srv in nonSecured_http)
            {
                Logger.InfoFormat("Stopping (http) on {0}", srv.Port);
                srv.Stop();
            }

            foreach (var srv in secured_http)
            {
                Logger.InfoFormat("Stopping (https) on {0}", srv.Port);
                srv.Stop();
            }*/
        }
        #endregion

        #region getName
        public string getName()
        {
            return GetType().Assembly.GetName().Name;
        }
        #endregion

        #region getVersion
        public string getVersion()
        {
            return GetType().Assembly.GetName().Version.ToString();
        }
        #endregion

        #region Message
        public void Message(dynamic message)
        {
            if (message != null)
            {
                foreach (var srv in nonSecured_ws)
                {
                    if (srv.IsListening)
                    {
                        var host = srv.WebSocketServices.Hosts.FirstOrDefault(ss => ss.Path.Equals("/console"));
                        if (host != null)
                        {
                            host.Sessions.Broadcast(JsonConvert.SerializeObject(message));
                            break;
                        }
                    }
                }

                foreach (var srv in secured_ws)
                {
                    if (srv.IsListening)
                    {
                        var host = srv.WebSocketServices.Hosts.FirstOrDefault(ss => ss.Path.Equals("/console"));
                        if (host != null)
                        {
                            host.Sessions.Broadcast(JsonConvert.SerializeObject(message));
                            break;
                        }
                    }
                }
            }
        }
        #endregion

        #region ResolveAssembly
        public Assembly ResolveAssembly(object sender, ResolveEventArgs args)
        {
            var assembly = (args.Name.Contains(","))
                    ? args.Name.Substring(0, args.Name.IndexOf(','))
                    : args.Name;

            var directory = Path.Combine(Environment.CurrentDirectory, "extensions");
            var plugin = getName() + "_" + getVersion() + ".zip";

            return Path.Combine(directory, plugin).GetAssemblyFromPlugin(assembly);
        }
        #endregion
    }
}
