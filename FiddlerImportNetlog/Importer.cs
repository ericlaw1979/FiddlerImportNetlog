using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
            // Sources
            public int URL_REQUEST;
            public int SOCKET;

            // Events
            public int REQUEST_ALIVE;
            public int URL_REQUEST_START_JOB;
            public int SEND_HEADERS;
            public int SEND_QUIC_HEADERS;
            public int SEND_HTTP2_HEADERS;
            public int READ_HEADERS;
            public int COOKIE_INCLUSION_STATUS;
            public int FILTERED_BYTES_READ;
            public int SEND_BODY;
            public int SEND_REQUEST;
            public int SSL_CERTIFICATES_RECEIVED;
            public int SSL_HANDSHAKE_MESSAGE_RECEIVED;
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
            // TODO: Something sane if o is null
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
        readonly EventHandler<ProgressCallbackEventArgs> _evtProgressNotifications;
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
            Hashtable htFile = JSON.JsonDecode(oSR.ReadToEnd(), out _) as Hashtable;
            if (null == htFile)
            {
                NotifyProgress(1.00f, "Aborting; file is not properly-formatted NetLog JSON.");
                FiddlerApplication.DoNotifyUser("This file is not properly-formatted NetLog JSON.", "Import aborted");
                return;
            }

            NotifyProgress(0.25f, "Finished parsing JSON file; took " + oSW.ElapsedMilliseconds + "ms.");
            if (!ExtractSessionsFromJSON(htFile))
            {
                FiddlerApplication.DoNotifyUser("This JSON file does not seem to contain NetLog data.", "Unexpected Data");
                Session sessFile = Session.BuildFromData(false,
                    new HTTPRequestHeaders(
                        String.Format("/file.json"),
                        new[] { "Host: IMPORTED", "Date: " + DateTime.UtcNow.ToString() }),
                    Utilities.emptyByteArray,
                    new HTTPResponseHeaders(200, "File Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                    Encoding.UTF8.GetBytes(JSON.JsonEncode(htFile)),
                    SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                listSessions.Insert(0, sessFile);
            }
        }

        private void NotifyProgress(float fPct, string sMessage)
        {
            _evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(fPct, sMessage));
        }

        private int getIntValue(object oValue, int iDefault)
        {
            if (null == oValue) return iDefault;
            if (!(oValue is Double)) return iDefault;
            return (int)(double)oValue;
        }

        public bool ExtractSessionsFromJSON(Hashtable htFile)
        {
            if (!(htFile["constants"] is Hashtable htConstants)) return false;
            if (!(htConstants["clientInfo"] is Hashtable htClientInfo)) return false;
            this.sClient = htClientInfo["name"] as string;

            #region LookupConstants
            Hashtable htEventTypes = htConstants["logEventTypes"] as Hashtable;
            Hashtable htNetErrors = htConstants["netError"] as Hashtable;
            Hashtable htSourceTypes = htConstants["logSourceType"] as Hashtable;

            // TODO: These should probably use a convenient wrapper for GetHashtableInt

            // Sources
            NetLogMagics.URL_REQUEST = getIntValue(htSourceTypes["URL_REQUEST"], -999);
            NetLogMagics.SOCKET = getIntValue(htSourceTypes["SOCKET"], -998);

            #region GetEventTypes
            // HTTP-level Events
            NetLogMagics.REQUEST_ALIVE = getIntValue(htEventTypes["REQUEST_ALIVE"], -987);
            NetLogMagics.URL_REQUEST_START_JOB = getIntValue(htEventTypes["URL_REQUEST_START_JOB"], -997);
            NetLogMagics.SEND_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_HEADERS"], -996);
            NetLogMagics.SEND_QUIC_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"], -995);
            NetLogMagics.SEND_HTTP2_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"], -994);
            NetLogMagics.READ_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_READ_RESPONSE_HEADERS"], -993);
            NetLogMagics.FILTERED_BYTES_READ = getIntValue(htEventTypes["URL_REQUEST_JOB_FILTERED_BYTES_READ"], -992);
            NetLogMagics.COOKIE_INCLUSION_STATUS = getIntValue(htEventTypes["COOKIE_INCLUSION_STATUS"], -991);
            NetLogMagics.SEND_BODY = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_BODY"], -990);
            NetLogMagics.SEND_REQUEST = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST"], -989);

            // Socket-level Events
            NetLogMagics.SSL_CERTIFICATES_RECEIVED = getIntValue(htEventTypes["SSL_CERTIFICATES_RECEIVED"], -988);
            NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED = getIntValue(htEventTypes["SSL_HANDSHAKE_MESSAGE_RECEIVED"], -987);

            // Get ALL event type names as strings for pretty print view
            dictEventTypes = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htEventTypes)
            {
                dictEventTypes.Add((int)(double)de.Value, de.Key as String);
            }
            #endregion

            #region GetNetErrors
            dictNetErrors = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htNetErrors)
            {
                dictNetErrors.Add((int)(double)de.Value, de.Key as String);
            }
            #endregion

            int iLogVersion = getIntValue(htConstants["logFormatVersion"], 0);
            NotifyProgress(0, "Found NetLog v" + iLogVersion + ".");
            #endregion LookupConstants

            #region GetBaseTime
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
            #endregion

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
                            String.Format("/ENABLED_EXTENSIONS"), // TODO: Add Machine name?
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(alExtensions)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));
            }

            int iEvent = -1;
            int iLastPct = 25;
            var dictURLRequests = new Dictionary<int, List<Hashtable>>();
            var dictSecureSockets = new Dictionary<int, List<Hashtable>>();

            // Loop over events; bucket those associated to URLRequests by the source request's ID.
            ArrayList alEvents = htFile["events"] as ArrayList;
            int cEvents = alEvents.Count;
            foreach (Hashtable htEvent in alEvents)
            {
                ++iEvent;
                var htSource = htEvent["source"] as Hashtable;
                if (null == htSource) continue;
                int iSourceType = getIntValue(htSource["type"], -1);

                #region ParseCertificateRequestMessagesAndDumpToLog
                if (iSourceType == NetLogMagics.SOCKET)
                {
                    try
                    {
                        // All events we care about should have parameters.
                        if (!(htEvent["params"] is Hashtable htParams)) continue;
                        int iType = getIntValue(htEvent["type"], -1);

                        List<Hashtable> events;
                        int iSocketID = getIntValue(htSource["id"], -1);

                        if (iType != NetLogMagics.SSL_CERTIFICATES_RECEIVED &&
                            iType != NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED) continue;

                        // Get (or create) the List of entries for this SOCKET.
                        if (!dictSecureSockets.ContainsKey(iSocketID))
                        {
                            events = new List<Hashtable>();
                            dictSecureSockets.Add(iSocketID, events);
                        }
                        else
                        {
                            events = dictSecureSockets[iSocketID];
                        }
                        // Add this event to the SOCKET's list.
                        events.Add(htEvent);
                    }
                    catch { }

                    continue;
                }
                #endregion ParseCertificateRequestMessagesAndDumpToLog

                // Collect only events related to URL_REQUESTS.
                if (iSourceType != NetLogMagics.URL_REQUEST) continue;

                int iURLRequestID = getIntValue(htSource["id"], -1);

                {
                    List<Hashtable> events;

                    // Get (or create) the List of entries for this URLRequest.
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
                }
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
            GenerateSocketListSession(dictSecureSockets);

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
                    // Store off the likely initial URL for this URL Request
                    string sUrl = String.Empty;

                    // Remove data we're unlikely to need, and replace magics with constant strings.
                    foreach (Hashtable ht in kvpURLRequest.Value)
                    {
                        ht.Remove("source");
                        ht.Remove("time");

                        try
                        {
                            // Replace Event type integers with names.
                            int iType = getIntValue(ht["type"], -1);
                            ht["type"] = dictEventTypes[iType];

                            if (iType == NetLogMagics.URL_REQUEST_START_JOB) {
                                sUrl = ((string)(ht["params"] as Hashtable)?["url"] ?? sUrl);
                            }

                            // Replace Event phase integers with names.
                            int iPhase = getIntValue(ht["phase"], -1);
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

                    htDebug.Add(String.Format("{0} - {1}", kvpURLRequest.Key, sUrl), alE);
                }

                if (htDebug.Count > 0)
                {
                    _listSessions.Add(Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/URL_REQUESTS"), // TODO: Add Machine name?
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(htDebug)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));
                }
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateDebugTreeSession failed: "+ DescribeExceptionWithStack(e)); }
        }

        private void GenerateSocketListSession(Dictionary<int, List<Hashtable>> dictSockets)
        {
            try
            {
                Hashtable htAllSockets = new Hashtable();
                foreach (KeyValuePair<int, List<Hashtable>> kvpSocket in dictSockets)
                {
                    string sSubjectCNinFirstCert = String.Empty;
                    Hashtable htThisSocket = new Hashtable();

                    foreach (Hashtable htEvent in kvpSocket.Value)
                    {
                        int iType = getIntValue(htEvent["type"], -1);
                        var htParams = (Hashtable) htEvent["params"];

                        if (iType == NetLogMagics.SSL_CERTIFICATES_RECEIVED)
                        {
                            StringBuilder sbCertsReceived = new StringBuilder();
                            ArrayList alCerts = htParams["certificates"] as ArrayList;

                            // Try to promote the SubjectCN to the title of this node
                            try
                            {
                                if (String.IsNullOrEmpty(sSubjectCNinFirstCert) && alCerts.Count > 0)
                                {
                                    var FirstCert = new X509Certificate2();
                                    string sCertInfo = alCerts[0] as string;
                                    FirstCert.Import(Encoding.ASCII.GetBytes(sCertInfo));
                                    sSubjectCNinFirstCert = (" - " + FirstCert.GetNameInfo(X509NameType.SimpleName, false)).ToLower();
                                }
                            }
                            catch { }
                            htThisSocket.Add("Server Certificates", alCerts);
                            continue;
                        }
                        // {"params":{"certificates":["-----BEGIN CERTIFICATE-----\nMIINqg==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\u4\n-----END CERTIFICATE-----\n"]},"phase":0,"source":{"id":789,"type":8},"time":"464074729","type":69},
                        // Parse out client certificate requests (Type 13==CertificateRequest)
                        // {"params":{"bytes":"DQA...","type":13},"phase":0,"source":{"id":10850,"type":8},"time":"160915359","type":60(SSL_HANDSHAKE_MESSAGE_RECEIVED)})
                        if (iType == NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED)
                        {
                            int iHandshakeMessageType = getIntValue(htParams["type"], -1);

                            if (iHandshakeMessageType != 13/*CertificateRequest*/) continue;

                            // Okay, it's a CertificateRequest. Log it.
                            string sBase64Bytes = htParams["bytes"] as string;
                            if (String.IsNullOrEmpty(sBase64Bytes)) continue;

                            // BORING SSL: https://cs.chromium.org/chromium/src/third_party/boringssl/src/ssl/handshake_client.cc?l=1102&rcl=5ce7022394055e183c12368778d361461fe90a6e

                            var htCertFilter = new Hashtable();
                            htThisSocket.Add("Request for Client Certificate", htCertFilter);
                            htThisSocket.Add("RAW", sBase64Bytes);

                            byte[] arrCertRequest = Convert.FromBase64String(sBase64Bytes);

                            Debug.Assert(13 == arrCertRequest[0]);
                            int iPayloadSize = (arrCertRequest[1] << 16) +
                                                (arrCertRequest[2] << 8) +
                                                arrCertRequest[3];

                            Debug.Assert(iPayloadSize == arrCertRequest.Length - 4);

                            byte cCertTypes = arrCertRequest[4];
                            var alCertTypes = new ArrayList();
                            for (int ixCertType = 0; ixCertType<cCertTypes; ++ixCertType)
                            {
                                int iCertType = arrCertRequest[5 + ixCertType];
                                string sCertType;
                                // https://tools.ietf.org/html/rfc5246#section-12 ClientCertificateType
                                switch (iCertType)
                                {
                                    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-2
                                    case 1: sCertType = "rsa_sign"; break;
                                    case 2: sCertType = "dss_sign"; break;
                                    case 3: sCertType = "rsa_fixed_dh"; break;
                                    case 4: sCertType = "dss_fixed_dh"; break;
                                    case 5: sCertType = "rsa_ephemeral_dh_RESERVED"; break;
                                    case 6: sCertType = "dss_ephemeral_dh_RESERVED"; break;
                                    case 20: sCertType = "fortezza_dms_RESERVED"; break;
                                    case 0x40: sCertType = "ecdsa_sign"; break;
                                    case 0x41: sCertType = "rsa_fixed_ecdh"; break;
                                    case 0x42: sCertType = "ecdsa_fixed_ecdh"; break;
                                    case 0x43: sCertType = "gost_sign256"; break;
                                    case 0x44: sCertType = "gost_sign512"; break;
                                    default: sCertType = String.Format("unknown(0x{0:x})", iCertType); break;
                                }
                                alCertTypes.Add(sCertType);
                            }
                            htCertFilter.Add("Accepted ClientCertificateTypes", alCertTypes);

                            int iPtr = 5 + cCertTypes;
                            int cbSigHashAlgs = (arrCertRequest[iPtr++] << 8) +
                                                 arrCertRequest[iPtr++];
                            Debug.Assert((cbSigHashAlgs % 2) == 0);

                            var alSigHashAlgs = new ArrayList();

                            // TODO: Only TLS/1.2+ have sig/hash pairs; these are omitted in TLS1.1 and earlier
                            for (int ixSigHashPair = 0; ixSigHashPair < cbSigHashAlgs/2; ++ixSigHashPair) {
                                alSigHashAlgs.Add(GetHashSigString(arrCertRequest[iPtr + (2*ixSigHashPair)], arrCertRequest[iPtr + (2*ixSigHashPair) + 1]));
                            }
                            htCertFilter.Add("Accepted SignatureAndHashAlgorithms", alSigHashAlgs);
                            iPtr += (cbSigHashAlgs);
                            //FiddlerApplication.Log.LogFormat("Found CertificateRequest on Socket #{0}:\n{1}", iSocketId, Fiddler.Utilities.ByteArrayToHexView(arrCertificateRequest, 24));
                            int cbCADistinguishedNames = (arrCertRequest[iPtr++] << 8) +
                                                          arrCertRequest[iPtr++];

                            try
                            {
                                var alCADNs = new ArrayList();
                                while (cbCADistinguishedNames > 0)
                                {
                                    int cbThisDN = (arrCertRequest[iPtr++] << 8) + arrCertRequest[iPtr++];
                                    Debug.Assert(cbThisDN < cbCADistinguishedNames);
                                    try
                                    {
                                        byte[] bytesDER = new byte[cbThisDN];
                                        Buffer.BlockCopy(arrCertRequest, iPtr, bytesDER, 0, cbThisDN);
                                        AsnEncodedData asndata = new AsnEncodedData(bytesDER);
                                        alCADNs.Add(new X500DistinguishedName(asndata).Name);
                                    }
                                    catch { Debug.Assert(false); }
                                    iPtr += cbThisDN;
                                    cbCADistinguishedNames -= (2 + cbThisDN);
                                }
                                htCertFilter.Add("Accepted Authorities", alCADNs);
                            }
                            catch { }

                            continue;
                        }
                    }

                    if (htThisSocket.Count > 0)
                    {
                        htAllSockets.Add(kvpSocket.Key + sSubjectCNinFirstCert, htThisSocket);
                    }
                }

                // Don't add a node if there were no secure sockets.
                if (htAllSockets.Count > 0)
                {
                    _listSessions.Add(Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/SECURE_SOCKETS"), // TODO: Add Machine name?
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(htAllSockets)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache));
                }
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateSocketListSession failed: " + DescribeExceptionWithStack(e)); }
        }

        private static string GetHashSigString(int iHash, int iSig)
        {
            string sHash;
            string sSig;
            switch (iHash)
            {
                // Hash https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
                case 0: sHash = "none"; break;
                case 1: sHash = "md5"; break;
                case 2: sHash = "sha1"; break;
                case 3: sHash = "sha224"; break;
                case 4: sHash = "sha256"; break;
                case 5: sHash = "sha384"; break;
                case 6: sHash = "sha512"; break;
                default: sHash = String.Format("unknown(0x{0:x})", iHash); break;
            }
            switch (iSig)
            {
                // Sigs https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-16
                case 0: sSig = "anonymous"; break;
                case 1: sSig = "rsa"; break;
                case 2: sSig = "dsa"; break;
                case 3: sSig = "ecdsa"; break;
                case 7: sSig = "ed25519"; break;
                case 8: sSig = "ed448"; break;
                case 64: sSig = "gostr34102012_256"; break;
                case 65: sSig = "gostr34102012_512"; break;
                default: sSig = String.Format("unknown(0x{0:x})", iSig); break;
            }
            return String.Format("{0}_{1}", sHash, sSig);
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

        // Each bucket contains all of the events associated with a URL_REQUEST, and each URL_REQUEST may contain
        // one or more (Auth, Redirects) Web Sessions.
        private void ParseSessionsFromBucket(KeyValuePair<int, List<Hashtable>> kvpUR)
        {
            List<Hashtable> listEvents = kvpUR.Value;

            SessionFlags oSF = SessionFlags.ImportedFromOtherTool | SessionFlags.ResponseStreamed;  // IsHTTPS?
            HTTPRequestHeaders oRQH = null;
            HTTPResponseHeaders oRPH = null;
            MemoryStream msResponseBody = new MemoryStream();
            Dictionary<string, string> dictSessionFlags = new Dictionary<string, string>();
            List<string> listCookieSendExclusions = new List<string>();
            List<string> listCookieSetExclusions = new List<string>();

            string sURL = String.Empty;
            string sMethod = "GET";
            string sTrafficAnnotation = String.Empty;
            SessionTimers oTimers = new SessionTimers();

            int cbDroppedResponseBody = 0;
            bool bHasStartJob = false;
            bool bHasSendRequest = false;

            foreach (Hashtable htEvent in listEvents)
            {
                try
                {
                    int iType = getIntValue(htEvent["type"], -1);
                    var htParams = htEvent["params"] as Hashtable;

                    // Most events we care about should have parameters.  LANDMINE_MEME HERE
                    if (iType != NetLogMagics.SEND_REQUEST && null == htParams) continue;

                    // FiddlerApplication.Log.LogFormat("URLRequest#{0} - Event type: {1} - {2}", kvpUR.Key, iType, sURL);

                    #region ParseImportantEvents
                    // C# cannot |switch()| on non-constant case values. Hrmph.
                    if (iType == NetLogMagics.REQUEST_ALIVE)
                    {
                        sTrafficAnnotation = getIntValue(htParams["traffic_annotation"], 0).ToString();
                        continue;
                    }

                    if (iType == NetLogMagics.URL_REQUEST_START_JOB)
                    {
                        // If we already had a URL_REQUEST_START_JOB on this URL_REQUEST, we are probably chasing a redirect.
                        // "finish" off the existing Session and start a new one at this point.
                        // TODO: This is really hacky right now.
                        if (bHasStartJob)
                        {
                            FiddlerApplication.Log.LogFormat("Got more than one START_JOB on URLRequest #{0} for {1}", kvpUR.Key, sURL);
                            AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
                            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
                            oRQH = null; oRPH = null; msResponseBody = new MemoryStream(); sURL = String.Empty; sMethod = "GET"; oTimers = new SessionTimers();
                            // We are effectively on a new request, don't act like we've seen headers for it before.
                            bHasSendRequest = false;
                            listCookieSetExclusions.Clear();
                            listCookieSendExclusions.Clear();
                            // ISSUE: There are probably some dictSessionFlags values that should be cleared here.
                        }

                        bHasStartJob = true;
                        sURL = (string)htParams["url"];
                        sMethod = (string)htParams["method"];
                        dictSessionFlags["X-Netlog-URLRequest-ID"] = kvpUR.Key.ToString();
                        dictSessionFlags["X-ProcessInfo"] = String.Format("{0}:0", sClient);
                        dictSessionFlags["X-Netlog-Traffic_Annotation"] = sTrafficAnnotation;

                        // In case we don't get these later.
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], baseTime);
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_REQUEST)
                    {
                        // Only look for "BEGIN" events.
                        if (getIntValue(htEvent["phase"], -1) != 1) continue;

                        // If we already had a SEND_REQUEST on this URL_REQUEST, we are probably in a HTTP Auth transaction.
                        // "finish" off the existing Session and start a new one at this point.
                        // TODO: This is really hacky right now.
                        if (bHasSendRequest)
                        {
                            FiddlerApplication.Log.LogFormat("Got more than one SendRequest on the URLRequest for {0}", sURL);
                            AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
                            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
                            // Keep sURL and sMethod, they shouldn't be changing.
                            oRQH = null; oRPH = null; msResponseBody = new MemoryStream(); oTimers = new SessionTimers();

                            listCookieSetExclusions.Clear();
                            listCookieSendExclusions.Clear();
                            // ISSUE: There are probably some dictSessionFlags values that should be cleared here.
                        }

                        bHasSendRequest = true;
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
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
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
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
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
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.COOKIE_INCLUSION_STATUS)
                    {
                        string sOperation = (htParams["operation"] as string) ?? String.Empty;
                        string sCookieName = (htParams["name"] as string) ?? "(name-unavailable)";

                        // Edge-specific fields
                        // bool bIsLegacyCookie = (htParams["msft_browser_legacy_cookie"] as Boolean) ?? false;
                        // string bBrowserProvenance = (htParams["browser_provenance"] as string) ?? String.Empty /*Native*/;

                        // TODO: As of Chrome 81, CookieInclusionStatusNetLogParams also adds |domain| and |path| attributes available if "sensitive" data is included.

                        // In Chrome 81.3993, the |exclusion_reason| field was renamed to |status| because the |cookie_inclusion_status| entries are
                        // now also emitted for included cookies.
                        string sExclusionReasons = (htParams["exclusion_reason"] as string);
                        if (String.IsNullOrEmpty(sExclusionReasons)) sExclusionReasons = (htParams["status"] as string) ?? String.Empty;

                        // If the log indicates that the cookie was included, just skip it for now.
                        // TODO: Offer a richer cookie-debugging story that exposes the domain/path/inclusion status.
                        // https://source.chromium.org/chromium/chromium/src/+/master:net/cookies/canonical_cookie.cc;l=899?q=GetDebugString%20cookie&ss=chromium&originalUrl=https:%2F%2Fcs.chromium.org%2F
                        if (sExclusionReasons.OICContains("include")) continue;

                        // See |ExclusionReason| list in https://cs.chromium.org/chromium/src/net/cookies/canonical_cookie.h?type=cs&q=EXCLUDE_SAMESITE_LAX&sq=package:chromium&g=0&l=304
                        // EXCLUDE_HTTP_ONLY, EXCLUDE_SECURE_ONLY,EXCLUDE_DOMAIN_MISMATCH,EXCLUDE_NOT_ON_PATH,EXCLUDE_INVALID_PREFIX
                        // EXCLUDE_SAMESITE_STRICT,EXCLUDE_SAMESITE_LAX,EXCLUDE_SAMESITE_EXTENDED,
                        // EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX,EXCLUDE_SAMESITE_NONE_INSECURE,
                        // EXCLUDE_USER_PREFERENCES,

                        if ("store" == sOperation)
                        {
                            // EXCLUDE_INVALID_DOMAIN,EXCLUDE_OVERWRITE_HTTP_ONLY,EXCLUDE_OVERWRITE_SECURE,EXCLUDE_FAILURE_TO_STORE,EXCLUDE_NONCOOKIEABLE_SCHEME
                            // EXCLUDE_INVALID_PREFIX
                            listCookieSetExclusions.Add(String.Format("Blocked set of '{0}' due to '{1}'", sCookieName, sExclusionReasons));
                        }
                        else if ("send" == sOperation)
                        {
                            // Don't warn about cookies which are obviously inapplicable
                            if (!new string[] { "EXCLUDE_DOMAIN_MISMATCH", "EXCLUDE_NOT_ON_PATH" }.Any(s => sExclusionReasons.Contains(s)))
                            {
                                listCookieSendExclusions.Add(String.Format("Blocked send of '{0}' due to '{1}'", sCookieName, sExclusionReasons));
                            }
                        }
                        else { Debug.Assert(false, "Unknown operation"); }

                        continue;
                    }

                    if (iType == NetLogMagics.SEND_BODY)
                    {
                        int iBodyLength = getIntValue(htParams["length"], 0);
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

                    // ISSUE: WHAT ABOUT "URL_REQUEST_JOB_BYTES_READ" BYTES? DONT WANT DUPLICATES.

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
                            cbDroppedResponseBody += getIntValue(htParams["byte_count"], 0);
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

            AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
        }

        private static void AnnotateHeadersWithUnsentCookies(HTTPRequestHeaders oRQH, List<string> listExclusions)
        {
            if (null == oRQH) return;
            foreach (string sExclusion in listExclusions) {
                oRQH.Add("$NETLOG-CookieNotSent", sExclusion);
            }

            listExclusions.Clear();
        }

        private static void AnnotateHeadersWithUnstoredCookies(HTTPResponseHeaders oRPH, List<string> listExclusions)
        {
            if (null == oRPH) return;
            foreach (string sExclusion in listExclusions)
            {
                oRPH.Add("$NETLOG-CookieNotSet", sExclusion);
            }

            listExclusions.Clear();
        }

        private void BuildAndAddSession(ref SessionFlags oSF, HTTPRequestHeaders oRQH, HTTPResponseHeaders oRPH, MemoryStream msResponseBody,
                                        Dictionary<string, string> dictSessionFlags, string sURL, string sMethod, SessionTimers oTimers, int cbDroppedResponseBody)
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

            if ((null != oRPH) && msResponseBody.Length > 0)
            {
                // Body bytes stored in the file were already unchunked and decompressed, so rename these
                // headers so we can use this session for AutoResponder playback, etc.
                oRPH.RenameHeaderItems("Content-Encoding", "X-Netlog-Removed-Content-Encoding");
                oRPH.RenameHeaderItems("Transfer-Encoding", "X-Netlog-Removed-Transfer-Encoding");
            }

            Session oS = Session.BuildFromData(false,
                oRQH,
                Utilities.emptyByteArray,
                oRPH,
                msResponseBody.ToArray(),
                oSF);

            // Store the URL from the URLRequest here, because it might have a URL Fragment in it, and the URL built
            // out of the headers definitely should not.
            if (oS.fullUrl != sURL) {
                oS["X-Netlog-URLRequest-URL"] = sURL;
            }

            // Attach the SessionFlags to the new Session.
            foreach (KeyValuePair<string, string> sFlag in dictSessionFlags)
            {
                oS[sFlag.Key] = sFlag.Value;
            }

            // Assign the timestamps we read from the events.
            oS.Timers = oTimers;

            _listSessions.Add(oS);
            // FiddlerApplication.Log.LogFormat("Added Session #{0}", oS.id);
        }

        // Chrome annoyingly uses both Hashtables (JS Object) and Arraylists (JS Array) to represent headers
        // depending on which event is in use.
        public static string HeadersToString(object o)
        {
            if (o is ArrayList) return HeaderArrayToHeaderString((ArrayList)o);
            if (o is Hashtable) return HeaderHashtableToHeaderString((Hashtable)o);
            if (null != o) Debug.Assert(false, "Unexpected header format");
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
