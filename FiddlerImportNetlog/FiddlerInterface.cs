using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Fiddler;

namespace FiddlerImportNetlog
{
    [ProfferFormat("NetLog JSON", "Chromium's JSON-based event log format (v1.1.1.2). See https://dev.chromium.org/for-testers/providing-network-details for more details.")]
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
                sFilename = Fiddler.Utilities.ObtainOpenFilename("Import " + sFormat, "NetLog JSON (*.json;*.json.gz)|*.json;*.json.gz");
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
                        Stream oFS = File.OpenRead(sFilename);

                        // Check to see if this file data was GZIP'd.
                        // TODO: Also check to see if the file header is PK and if so, unzip it, and for each file in it, check to see if it's a Netlog capture.
                        bool bWasGZIP = false;
                        if (oFS.ReadByte() == 0x1f && oFS.ReadByte() == 0x8b)
                        {
                            bWasGZIP = true;
                            evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(0, "File was compressed using gzip/DEFLATE"));
                        }

                        oFS.Position = 0;
                        if (bWasGZIP)
                        {
                            oFS = GetUnzippedBytes(oFS);
                        }

                        oSR = new StreamReader(oFS, Encoding.UTF8);
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

        /// <summary>
        /// Read the all bytes of the supplied DEFLATE-compressed file and return a memorystream containing the expanded bytes.
        /// </summary>
        private MemoryStream GetUnzippedBytes(Stream oFS)
        {
            long fileLength = oFS.Length;
            if (fileLength > Int32.MaxValue)
                throw new IOException("file over 2gb");
            
            int index = 0;
            int count = (int)fileLength;
            byte[] bytes = new byte[count];

            while (count > 0)
            {
                int n = oFS.Read(bytes, index, count);
                index += n;
                count -= n;
            }

            return new MemoryStream(Utilities.GzipExpand(bytes));
        }

        public void Dispose() { }
    }
}