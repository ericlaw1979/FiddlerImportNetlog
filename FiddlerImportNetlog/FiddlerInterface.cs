using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Fiddler;

namespace FiddlerImportNetlog
{
    [ProfferFormat("NetLog JSON", "Chromium's JSON-based event log format (v1.1.1.1). See https://dev.chromium.org/for-testers/providing-network-details for more details.")]
    public class HTTPArchiveFormatImport : ISessionImporter
    {
        public Session[] ImportSessions(string sFormat, Dictionary<string, object> dictOptions, EventHandler<Fiddler.ProgressCallbackEventArgs> evtProgressNotifications)
        {
            if ((sFormat != "NetLog JSON")) { Debug.Assert(false); return null; }

            MemoryStream strmContent = null;
            string sFilename = null;
            if (null != dictOptions)
            {
                if (dictOptions.ContainsKey("Filename"))
                {
                    sFilename = dictOptions["Filename"] as string;
                }
                else if (dictOptions.ContainsKey("Content"))
                {
                    strmContent = new MemoryStream(Encoding.UTF8.GetBytes(dictOptions["Content"] as string));
                }
            }

            if ((null == strmContent) && string.IsNullOrEmpty(sFilename))
            {
                sFilename = Fiddler.Utilities.ObtainOpenFilename("Import " + sFormat, "NetLog JSON (*.json)|*.json");
            }

            if ((null != strmContent) || !String.IsNullOrEmpty(sFilename))
            {
                try
                {
                    List<Session> listSessions = new List<Session>();
                    StreamReader oSR;

                    if (null != strmContent)
                    {
                        oSR = new StreamReader(strmContent);
                    }
                    else
                    {
                        oSR = new StreamReader(sFilename, Encoding.UTF8);
                    }

                    using (oSR)
                    {
                        new NetlogImporter(oSR, listSessions, evtProgressNotifications);
                    }
                    return listSessions.ToArray();
                }
                catch (Exception eX)
                {
                    FiddlerApplication.ReportException(eX, "Failed to import NetLog");
                    return null;
                }
            }
            return null;
        }

        public void Dispose() { }
    }
}