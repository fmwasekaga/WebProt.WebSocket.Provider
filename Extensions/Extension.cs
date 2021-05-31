﻿using Plugable.io;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using WebSocketSharp.Server;

namespace WebProt.WebSocket.Provider.Extensions
{
    public static class Extension
    {
        #region Plugins
        public static WebSocketServer Plugins(this WebSocketServer server, List<IProtocolPlugin> plugins, string[] args, PluginsManager parent)
        {
            if (plugins != null)
            {
                foreach (var plugin in plugins)
                {
                    if (plugin != null)
                        plugin.Initialize(args, parent, server);
                }
            }
            return server;
        }

        public static HttpServer Plugins(this HttpServer server, List<IProtocolPlugin> plugins, string[] args, PluginsManager parent)
        {
            if (plugins != null)
            {
                foreach (var plugin in plugins)
                {
                    if (plugin != null)
                        plugin.Initialize(args, parent, server);
                }
            }
            return server;
        }
        #endregion

        #region Log/Error
        private static string LogMessage(string message, string title, bool writeToFile, string callingMethod, string callingFilePath, int callingFileLineNumber, bool includeHeader = true)
        {
            var stringBuilder = new StringBuilder();
            if (includeHeader)
            {
                if (writeToFile && !string.IsNullOrEmpty(message))
                {
                    if (!Directory.Exists("logs")) Directory.CreateDirectory("logs");

                    var info = callingMethod + Environment.NewLine;
                    info += callingFilePath + Environment.NewLine;
                    info += callingFileLineNumber + Environment.NewLine;
                    info += Environment.NewLine + Environment.NewLine;
                    info += message;

                    var file = DateTime.Now.ToString("yyyy_MM_dd_hh_mm_ss_", CultureInfo.InvariantCulture) + title.ToLower() + ".txt";
                    File.WriteAllText(Path.Combine("logs", file), info);
                }
                stringBuilder.Append(DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture));
                stringBuilder.Append(" ");


                // Append a readable representation of the log level
                stringBuilder.Append(("[" + title.ToUpper() + "]").PadRight(8));
            }
            stringBuilder.Append("(" + callingMethod + " : " + callingFileLineNumber + ") ");

            // Append the message
            stringBuilder.Append(message);

            return stringBuilder.ToString();
        }

        public static void Log(string message,
            bool writeToFile = false,
            [CallerMemberName] string callingMethod = null,
            [CallerFilePath] string callingFilePath = null,
            [CallerLineNumber] int callingFileLineNumber = 0)
        {
            //lock (errorState)
            {
                Console.ForegroundColor = ConsoleColor.White;
                var msg = LogMessage(message, "INFO", writeToFile, callingMethod, callingFilePath, callingFileLineNumber);
                Console.WriteLine(msg);
                Console.ResetColor();
            }
        }

        public static void Error(string message,
            bool writeToFile = true,
            [CallerMemberName] string callingMethod = null,
            [CallerFilePath] string callingFilePath = null,
            [CallerLineNumber] int callingFileLineNumber = 0)
        {
            //lock (lockState)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                var msg = LogMessage(message, "ERROR", writeToFile, callingMethod, callingFilePath, callingFileLineNumber);
                Console.WriteLine(msg);
                Console.ResetColor();
            }
        }
        #endregion

        #region ToArguments
        public static string[] ToArguments(this string commandLine)
        {
            char[] parmChars = commandLine.ToCharArray();
            bool inQuote = false;
            for (int index = 0; index < parmChars.Length; index++)
            {
                if (parmChars[index] == '"')
                    inQuote = !inQuote;
                if (!inQuote && parmChars[index] == ' ')
                    parmChars[index] = '\n';
            }
            return (new string(parmChars)).Split('\n');
        }
        #endregion
    }
}
