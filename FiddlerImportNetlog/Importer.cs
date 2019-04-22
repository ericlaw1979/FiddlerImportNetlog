using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Fiddler;
using Fiddler.WebFormats;

namespace FiddlerImportNetlog
{
    class NetlogImporter
    {
        /// <summary>
        /// The Netlog file itself contains the mapping between string constants and the magic numbers used in the event entries.
        /// </summary>
        struct Magics
        {
            public int URL_REQUEST;
            public int URL_REQUEST_START_JOB;
            public int SEND_HEADERS;
            public int SEND_QUIC_HEADERS;
            public int SEND_HTTP2_HEADERS;
            public int READ_HEADERS;
            public int FILTERED_BYTES_READ;
            public int SEND_BODY;
        }

        internal static string DescribeExceptionWithStack(Exception eX)
        {
            StringBuilder oSB = new StringBuilder(512);
            oSB.AppendLine(eX.Message);
            oSB.AppendLine(eX.StackTrace);
            if (null != eX.InnerException)
            {
                oSB.AppendFormat(" < {0}", eX.InnerException.Message);
            }
            return oSB.ToString();
        }

        /// <summary>
        /// Remove disabled extensions, and any name/value pairs where the value is empty.
        /// </summary>
        private static ArrayList FilterExtensions(ArrayList al)
        {
            ArrayList alOut = new ArrayList();
            if (null != al)
            {
                foreach (Hashtable htItem in al)
                {
                    if ((bool)htItem["enabled"])
                    {
                        List<string> keysToDrop = new List<string> { "enabled", "kioskOnly", "kioskEnabled", "offlineEnabled" };
                        foreach (DictionaryEntry kvp in htItem)
                        {
                            if ((kvp.Value is string) && String.IsNullOrWhiteSpace(kvp.Value as string)) keysToDrop.Add(kvp.Key as string);
                        }
                        foreach (string key in keysToDrop) htItem.Remove(key);
                        alOut.Add(htItem);
                    }
                }
            }
            return alOut;
        }
        
        private static DateTime GetTimeStamp(object o, long baseTime)
        {
            long t = baseTime;
            if (o is string)
            {
                t += Int64.Parse(o as string);
            }
            else
            {
                t += (long)(double)o;
            }
            return DateTimeOffset.FromUnixTimeMilliseconds(t).DateTime.ToLocalTime();
        }

        List<Session> _listSessions;
        EventHandler<ProgressCallbackEventArgs> _evtProgressNotifications;
        Magics NetLogMagics;

        string sClient;
        long baseTime;
        Dictionary<int, string> dictEventTypes;
        Dictionary<int, string> dictNetErrors;

        internal NetlogImporter(StreamReader oSR, List<Session> listSessions, EventHandler<ProgressCallbackEventArgs> evtProgressNotifications)
        {
            _listSessions = listSessions;
            _evtProgressNotifications = evtProgressNotifications;

            Stopwatch oSW = Stopwatch.StartNew();
            JSON.JSONParseErrors oErrors;
            Hashtable htFile = JSON.JsonDecode(oSR.ReadToEnd(), out oErrors) as Hashtable;
            if (null == htFile)
            {
                NotifyProgress(1.00f, "Aborting; file is not properly-formatted NetLog JSON.");
                FiddlerApplication.DoNotifyUser("This file is not properly-formatted NetLog JSON.", "Import aborted");
                return;
            }

            NotifyProgress(0.25f, "Finished parsing JSON file; took " + oSW.ElapsedMilliseconds + "ms.");
            ExtractSessionsFromJSON(htFile);
        }

        private void NotifyProgress(float fPct, string sMessage)
        {
            _evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(fPct, sMessage));
        }

        public bool ExtractSessionsFromJSON(Hashtable htFile)
        {
            Hashtable htConstants = htFile["constants"] as Hashtable;
            Hashtable htClientInfo = htConstants["clientInfo"] as Hashtable;
            sClient = htClientInfo["name"] as string;

            #region LookupConstants
            Hashtable htEventTypes = htConstants["logEventTypes"] as Hashtable;
            Hashtable htNetErrors = htConstants["netError"] as Hashtable;
            Hashtable htSourceTypes = htConstants["logSourceType"] as Hashtable;
            NetLogMagics.URL_REQUEST = (int)(double)htSourceTypes["URL_REQUEST"];

            NetLogMagics.URL_REQUEST_START_JOB = (int)(double)htEventTypes["URL_REQUEST_START_JOB"];

            NetLogMagics.SEND_HEADERS = (int)(double)htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_HEADERS"];
            NetLogMagics.SEND_QUIC_HEADERS = (int)(double)htEventTypes["HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"];
            NetLogMagics.SEND_HTTP2_HEADERS = (int)(double)htEventTypes["HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"];

            NetLogMagics.READ_HEADERS = (int)(double)htEventTypes["HTTP_TRANSACTION_READ_RESPONSE_HEADERS"];
            NetLogMagics.FILTERED_BYTES_READ = (int)(double)htEventTypes["URL_REQUEST_JOB_FILTERED_BYTES_READ"];
            NetLogMagics.SEND_BODY = (int)(double)htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_BODY"];
            #endregion LookupConstants

            dictEventTypes = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htEventTypes)
            {
                dictEventTypes.Add((int)(double)de.Value, de.Key as String);
            }

            dictNetErrors = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htNetErrors)
            {
                dictNetErrors.Add((int)(double)de.Value, de.Key as String);
            }

            int iLogVersion = (int)(double)htConstants["logFormatVersion"];
            NotifyProgress(0, "Found NetLog v" + iLogVersion + ".");

            // Base time for all events' relative timestamps.
            object o = htConstants["timeTickOffset"];
            if (o is string)
            {
                baseTime = Int64.Parse(o as string);
            }
            else
            {
                baseTime = (long)(double)o;
            }
            DateTimeOffset dtBase = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeMilliseconds(baseTime), TimeZoneInfo.Local);
            FiddlerApplication.Log.LogFormat("Base capture time is {0} aka {1}", baseTime, dtBase);


            // Create a Summary Session, the response body of which we'll fill in later.
            Session sessSummary = Session.BuildFromData(false,
                    new HTTPRequestHeaders(
                        String.Format("/CAPTURE_INFO"), // TODO: Add Machine name?
                        new[] { "Host: NETLOG" /* TODO: Put something useful here */, "Date: " + dtBase.ToString("r") }),
                    Utilities.emptyByteArray,
                    new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: text/plain; charset=utf-8" }),
                    Utilities.emptyByteArray,
                    SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
            _listSessions.Add(sessSummary);

            _listSessions.Add(Session.BuildFromData(false,
                new HTTPRequestHeaders(
                    String.Format("/RAW_JSON"), // TODO: Add Machine name?
                    new[] { "Host: NETLOG" }),
                Utilities.emptyByteArray,
                new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                Encoding.UTF8.GetBytes(JSON.JsonEncode(htFile)),
                SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));

            Hashtable htPolledData = htFile["polledData"] as Hashtable;
            if (null != htPolledData)
            {
                ArrayList alExtensions = FilterExtensions(htPolledData["extensionInfo"] as ArrayList);

                _listSessions.Add(Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/Enabled_Extensions"), // TODO: Add Machine name?
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(alExtensions)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));
            }

            
            ArrayList alEvents = htFile["events"] as ArrayList;

            var dictURLRequests = new Dictionary<int, List<Hashtable>>();

            int cEvents = alEvents.Count;
            int iEvent = -1;
            int iLastPct = 25;

            // Loop over events; bucket those associated to URLRequests by the source request's ID.
            foreach (Hashtable htEvent in alEvents)
            {
                ++iEvent;
                var htSource = htEvent["source"] as Hashtable;
                if (null == htSource) continue;

                // Collect only events related to URL_REQUESTS.
                if ((int)(double)htSource["type"] != NetLogMagics.URL_REQUEST) continue;

                int iURLRequestID = (int)(double)htSource["id"];

                List<Hashtable> events;

                if (!dictURLRequests.ContainsKey(iURLRequestID))
                {
                    events = new List<Hashtable>();
                    dictURLRequests.Add(iURLRequestID, events);
                }
                else
                {
                    events = dictURLRequests[iURLRequestID];
                }

                // Add this event to the URLRequest's list.
                events.Add(htEvent);
                int iPct = (int)(100 * (0.25f + 0.50f * (iEvent / (float)cEvents)));
                if (iPct != iLastPct)
                {
                    NotifyProgress(iPct / 100f, "Parsed an event for a URLRequest");
                    iLastPct = iPct;
                }
            }

            int cURLRequests = dictURLRequests.Count;

            NotifyProgress(0.75f, "Finished reading event entries, saw " + cURLRequests.ToString() + " URLRequests");

            iLastPct = GenerateSessionsFromURLRequests(dictURLRequests);

            StringBuilder sbClientInfo = new StringBuilder();
            sbClientInfo.AppendFormat("Client:\t\t{0} v{1}\n", sClient, htClientInfo["version"]);
            sbClientInfo.AppendFormat("Channel:\t\t{0}\n", htClientInfo["version_mod"]);
            sbClientInfo.AppendFormat("Commit Hash:\t{0}\n", htClientInfo["cl"]);
            sbClientInfo.AppendFormat("OS:\t\t{0}\n", htClientInfo["os_type"]);

            sbClientInfo.AppendFormat("\nCommandLine:\t{0}\n\n", htClientInfo["command_line"]);
            sbClientInfo.AppendFormat("Capture started:\t{0}\n", dtBase);
            sbClientInfo.AppendFormat("URLRequests:\t{0} found.\n", cURLRequests);

            sessSummary.utilSetResponseBody(sbClientInfo.ToString());

            GenerateDebugTreeSession(dictURLRequests);

            NotifyProgress(1, "Import Completed.");
            return true;
        }

        /// <summary>
        /// Add a JSON session of the URL_REQUEST buckets for diagnostic purposes.
        /// WARNING: LOSSY. MANGLES TREE. DO THIS LAST.
        /// </summary>
        /// <param name="dictEventTypes"></param>
        /// <param name="dictNetErrors"></param>
        /// <param name="dictURLRequests"></param>
        private void GenerateDebugTreeSession(Dictionary<int, List<Hashtable>> dictURLRequests)
        {
            try
            {
                Hashtable htDebug = new Hashtable();
                foreach (KeyValuePair<int, List<Hashtable>> kvpURLRequest in dictURLRequests)
                {
                    // Remove data we're unlikely to need, and replace magics with constant strings.
                    foreach (Hashtable ht in kvpURLRequest.Value)
                    {
                        ht.Remove("source");
                        ht.Remove("time");

                        try
                        {
                            // Replace Event type integers with names.
                            int iType = (int)(double)ht["type"];
                            ht["type"] = dictEventTypes[iType];

                            // Replace Event phase integers with names.
                            int iPhase = (int)(double)ht["phase"];
                            ht["phase"] = (iPhase == 1) ? "BEGIN" : (iPhase == 2) ? "END" : "NONE";

                            // Replace NetError integers with names.
                            Hashtable htParams = ht["params"] as Hashtable;
                            if (null != htParams && htParams["net_error"] is Double d)
                            {
                                int iErr = (int)d;
                                if (iErr != 0) // 0 isn't valid; NetErrors are usually negative.
                                {
                                    htParams["net_error"] = dictNetErrors[iErr];
                                }
                            }
                        }
                        catch (Exception e) { FiddlerApplication.Log.LogFormat(DescribeExceptionWithStack(e)); }
                    }

                    // Copy List<Hashtable> to ArrayList, which is the only type the serializer understands.
                    ArrayList alE = new ArrayList(kvpURLRequest.Value);
                    htDebug.Add(kvpURLRequest.Key, alE);
                }

                _listSessions.Add(Session.BuildFromData(false,
                    new HTTPRequestHeaders(
                        String.Format("/URL_REQUESTS"), // TODO: Add Machine name?
                        new[] { "Host: NETLOG" }),
                    Utilities.emptyByteArray,
                    new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                    Encoding.UTF8.GetBytes(JSON.JsonEncode(htDebug)),
                    SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateDebugTreeSession failed: "+ DescribeExceptionWithStack(e)); }
        }

        private int GenerateSessionsFromURLRequests(Dictionary<int, List<Hashtable>> dictURLRequests)
        {
            int cURLRequests = dictURLRequests.Count;
            int iLastPct;
            int iRequest = 0;
            iLastPct = 75;

            // Iterate over each URLRequest's events bucket and parse one or more Sessions out of it. 
            foreach (KeyValuePair<int, List<Hashtable>> kvpUR in dictURLRequests)
            {
                ++iRequest;
                ParseSessionsFromBucket(kvpUR);
                int iPct = (int)(100 * (0.75f + 0.25f * (iRequest / (float)cURLRequests)));
                if (iPct != iLastPct)
                {
                    NotifyProgress(iPct / 100f, "Completed analysis of URLRequest");
                    iLastPct = iPct;
                }
            }

            return iLastPct;
        }

        private void ParseSessionsFromBucket(KeyValuePair<int, List<Hashtable>> kvpUR)
        {
            List<Hashtable> listEvents = kvpUR.Value;

            SessionFlags oSF = SessionFlags.ImportedFromOtherTool | SessionFlags.ResponseStreamed;  // IsHTTPS?
            HTTPRequestHeaders oRQH = null;
            HTTPResponseHeaders oRPH = null;
            MemoryStream msResponseBody = new MemoryStream();
            Dictionary<string, string> dictSessionFlags = new Dictionary<string, string>();
            string sURL = String.Empty;
            string sMethod = "GET";
            SessionTimers oTimers = new SessionTimers();

            int cbDroppedResponseBody = 0;
            bool bHasStartJob = false;

            foreach (Hashtable htEvent in listEvents)
            {
                try
                {
                    int iType = (int)(double)htEvent["type"];
                    var htParams = htEvent["params"] as Hashtable;

                    // All events we care about should have parameters.
                    if (null == htParams) continue;

                    #region ParseImportantEvents
                    // C# cannot |switch()| on non-constant case values. Hrmph.
                    if (iType == NetLogMagics.URL_REQUEST_START_JOB)
                    {
                        if (bHasStartJob)
                        {
                            // "finish" off the existing Session and start a new one at this point.
                            //
                            // TODO: This is really hacky right now.
                            FiddlerApplication.Log.LogFormat("Got more than one start job on the URLRequest for {0}", sURL);
                            BuildAndAddSession(ref oSF, ref oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
                            oRQH = null; oRPH = null; msResponseBody = new MemoryStream(); sURL = String.Empty; sMethod = "GET"; oTimers = new SessionTimers();
                        }

                        bHasStartJob = true;
                        sURL = (string)htParams["url"];
                        sMethod = (string)htParams["method"];
                        dictSessionFlags["X-Netlog-URLRequest-ID"] = kvpUR.Key.ToString();
                        dictSessionFlags["X-ProcessInfo"] = String.Format("{0}:0", sClient);

                        // In case we don't get these later.
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], baseTime);
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_HEADERS)
                    {
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], baseTime);
                        ArrayList alHeaderLines = htParams["headers"] as ArrayList;
                        if (null != alHeaderLines && alHeaderLines.Count > 0)
                        {
                            string sRequest = sMethod + " " + sURL + " HTTP/1.1\r\n" + String.Join("\r\n", alHeaderLines.Cast<string>().ToArray());
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_QUIC_HEADERS)
                    {
                        dictSessionFlags["X-Transport"] = "QUIC";
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], baseTime);
                        string sRequest = HeadersToString(htParams["headers"]);
                        if (!String.IsNullOrEmpty(sRequest))
                        {
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_HTTP2_HEADERS)
                    {
                        dictSessionFlags["X-Transport"] = "HTTP2";
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], baseTime);
                        string sRequest = HeadersToString(htParams["headers"]);
                        if (!String.IsNullOrEmpty(sRequest))
                        {
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_BODY)
                    {
                        int iBodyLength = (int)(double)htParams["length"];
                        if (iBodyLength > 0)
                        {
                            oSF |= SessionFlags.RequestBodyDropped;
                            dictSessionFlags["X-RequestBodyLength"] = iBodyLength.ToString("N0");
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.READ_HEADERS)
                    {
                        ArrayList alHeaderLines = htParams["headers"] as ArrayList;
                        oTimers.ServerBeginResponse = oTimers.FiddlerGotResponseHeaders = GetTimeStamp(htEvent["time"], baseTime);
                        if (null != alHeaderLines && alHeaderLines.Count > 0)
                        {
                            string sResponse = string.Join("\r\n", alHeaderLines.Cast<string>().ToArray());
                            oRPH = Fiddler.Parser.ParseResponse(sResponse);
                        }
                        continue;
                    }

                    // ISSUE: WHAT ABOUT  "URL_REQUEST_JOB_BYTES_READ" BYTES? DONT WANT DUPLICATES.

                    if (iType == NetLogMagics.FILTERED_BYTES_READ)
                    {
                        string sBase64Bytes = htParams["bytes"] as string;
                        if (!String.IsNullOrEmpty(sBase64Bytes))
                        {
                            byte[] arrThisRead = Convert.FromBase64String(sBase64Bytes);
                            msResponseBody.Write(arrThisRead, 0, arrThisRead.Length); // WTF, why so verbose?
                        }
                        else
                        {
                            cbDroppedResponseBody += (int)(double)htParams["byte_count"];
                        }
                        continue;
                    }
                }
                catch (Exception eX)
                {
                    FiddlerApplication.Log.LogFormat("Parsing event failed:\n{0}", DescribeExceptionWithStack(eX));
                }
                #endregion ParseImportantEvents
            }

            BuildAndAddSession(ref oSF, ref oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
        }

        private void BuildAndAddSession(ref SessionFlags oSF, ref HTTPRequestHeaders oRQH, HTTPResponseHeaders oRPH, MemoryStream msResponseBody, Dictionary<string, string> dictSessionFlags, string sURL, string sMethod, SessionTimers oTimers, int cbDroppedResponseBody)
        {
            // TODO: Sanity-check missing headers.
            if (null == oRQH && !String.IsNullOrWhiteSpace(sURL))
            {
                oRQH = Fiddler.Parser.ParseRequest(sMethod + " " + sURL + " HTTP/1.1\r\nMissing-Data: Request Headers not captured in NetLog\r\n\r\n");
            }
            if (msResponseBody.Length < 1 && cbDroppedResponseBody > 0)
            {
                dictSessionFlags["X-RESPONSEBODYTRANSFERLENGTH"] = cbDroppedResponseBody.ToString("N0");
                oSF |= SessionFlags.ResponseBodyDropped;
            }

            if (null != oRQH)
            {
                // Body bytes stored in the file were already decompressed, so rename the header so we can use this
                // session for AutoResponder playback, etc.
                oRQH.RenameHeaderItems("Content-Encoding", "X-Netlog-Removed-Content-Encoding");
            }

            Session oS = Session.BuildFromData(false,
                oRQH,
                Utilities.emptyByteArray,
                oRPH,
                msResponseBody.ToArray(),
                oSF);

            // Attach the SessionFlags to the new Session.
            foreach (KeyValuePair<string, string> sFlag in dictSessionFlags)
            {
                oS[sFlag.Key] = sFlag.Value;
            }

            // Assign the timestamps we read from the events.
            oS.Timers = oTimers;

            _listSessions.Add(oS);
        }

        // Chrome annoyingly uses both Hashtables (JS Object) and Arraylists (JS Array) to represent headers
        // depending on which event is in use.
        public static string HeadersToString(object o)
        {
            if (o is ArrayList) return HeaderArrayToHeaderString((ArrayList)o);
            if (o is Hashtable) return HeaderHashtableToHeaderString((Hashtable)o);
            return String.Empty;
        }

        private static string HeaderHashtableToHeaderString(Hashtable ht)
        {
            if (null == ht || ht.Count < 1) return String.Empty;

            string sMethod = "MISSING";
            string sScheme = "MISSING";
            string sAuthority = "MISSING";
            string sPath = "/MISSING";
            List<string> slHeaders = new List<string>();

            foreach (DictionaryEntry de in ht)
            {
                KeyValuePair<string, string> kvp = new KeyValuePair<string, string>((string)de.Key, (string)de.Value);
                if (kvp.Key.StartsWith(":"))
                {
                    if (kvp.Key.Equals(":method")) { sMethod = kvp.Value; continue; }
                    if (kvp.Key.Equals(":scheme")) { sScheme = kvp.Value; continue; }
                    if (kvp.Key.Equals(":authority")) { sAuthority = kvp.Value; continue; }
                    if (kvp.Key.Equals(":path")) { sPath = kvp.Value; continue; }
                }
                slHeaders.Add(kvp.Key + ": " + kvp.Value);
            }

            return String.Format("{0} {1}://{2}{3} {4}\r\n{5}",
                sMethod, sScheme, sAuthority, sPath, "HTTP/1.1",
                String.Join("\r\n", slHeaders.ToArray()));
        }

        private static string HeaderArrayToHeaderString(ArrayList alIn)
        {
            if (null == alIn || alIn.Count < 1) return String.Empty;

            string sMethod = "MISSING";
            string sScheme = "MISSING";
            string sAuthority = "MISSING";
            string sPath = "/MISSING";
            List<string> slHeaders = new List<string>();

            foreach (string s in alIn)
            {
                if (s.StartsWith(":"))
                {
                    if (s.StartsWith(":method: ")) { sMethod = s.Substring(9); continue; }
                    if (s.StartsWith(":scheme: ")) { sScheme = s.Substring(9); continue; }
                    if (s.StartsWith(":authority: ")) { sAuthority = s.Substring(12); continue; }
                    if (s.StartsWith(":path: ")) { sPath = s.Substring(7); continue; }
                }
                slHeaders.Add(s);
            }

            return String.Format("{0} {1}://{2}{3} {4}\r\n{5}",
                sMethod, sScheme, sAuthority, sPath, "HTTP/1.1",
                String.Join("\r\n", slHeaders.ToArray()));
        }

    }
}
