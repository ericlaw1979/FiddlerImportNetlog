/// <remarks>
/// Originally based on http://techblog.procurios.nl/k/618/news/view/14605/14863/How-do-I-write-my-own-parser-for-JSON.html
/// Licensed under the http://www.opensource.org/licenses/mit-license.php by Patrick van Bergen.
/// Modified based on real-world experience.
///</remarks>
using Fiddler;
using System;
using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace FiddlerImportNetlog.WebFormats
{
    /// <summary>
    /// This class encodes and decodes JSON text http://www.json.org/
    /// JSON uses Arrays and Objects, similar to DotNet datatypes ArrayList and Hashtable.
    /// All numbers are parsed to doubles.
    /// </summary>
    public class JSON
    {
        /// <summary>
        /// Wrapper around JSON Parse output; needed because JScript.NET does not support OUT Parameters
        /// </summary>
        public class JSONParseResult
        {
            public object JSONObject
            {
                get;
                set;
            }
            public JSONParseErrors JSONErrors
            {
                get;
                set;
            }
        }

        public class JSONParseErrors
        {
            /// <summary>
            /// Index of the last error in the stream
            /// </summary>
            public int iErrorIndex { get; set; }

            /// <summary>
            /// Warnings found while parsing JSON
            /// </summary>
            public string sWarningText { get; set; }
        }

        internal enum JSONTokens : byte
        {
            NONE = 0,
            CURLY_OPEN = 1,
            CURLY_CLOSE = 2,
            SQUARED_OPEN = 3,
            SQUARED_CLOSE = 4,
            COLON = 5,
            COMMA = 6,
            STRING = 7,
            NUMBER = 8,
            TRUE = 9,
            FALSE = 10,
            NULL = 11,
            /// <summary>
            /// This token is a JavaScript Identifier that was not properly quoted as it should have been.
            /// </summary>
            IMPLIED_IDENTIFIER_NAME = 12
            // Note: We don't allow Regular Expressions in JSON as they are not allowed per-spec
        }

        private const int BUILDER_DEFAULT_CAPACITY = 2048;

        // This result type should have been JSONParseResult. Probably can't change it now. Sigh.
        public static object JsonDecode(string sJSON)
        {
            JSONParseResult oResult = new JSONParseResult();
            JSONParseErrors oErrors; 
            oResult.JSONObject = JsonDecode(sJSON, out oErrors);
            oResult.JSONErrors = oErrors;
            return oResult;
        }

        /// <summary>
        /// Parses the JSON string into an object
        /// </summary>
        /// <param name="json">A JSON string.</param>
        /// <returns>An ArrayList, a Hashtable, a double, a string, null, true, or false</returns>
        public static object JsonDecode(string sJSON, out JSONParseErrors oErrors)
        {
            oErrors = new JSONParseErrors() { iErrorIndex = -1, sWarningText = String.Empty };
            if (!String.IsNullOrEmpty(sJSON))
            {
                char[] charArray = sJSON.ToCharArray();
                int index = 0;
                bool success = true;
                object value = ParseValue(charArray, ref index, ref success, ref oErrors);
                return value;
            } 
            else 
            {
                return null;
            }
        }

        private static Hashtable ParseObject(char[] json, ref int index, ref JSONParseErrors oErrors)
        {
            Hashtable htThisObject = new Hashtable();
            JSONTokens jtToken;

            NextToken(json, ref index);

            bool done = false;
            while (!done) 
            {
                jtToken = LookAhead(json, index);
                if (jtToken == JSONTokens.NONE)
                {
                    return null;
                }
                else if (jtToken == JSONTokens.COMMA)
                {
                    NextToken(json, ref index);
                }
                else if (jtToken == JSONTokens.CURLY_CLOSE)
                {
                    NextToken(json, ref index);
                    return htThisObject;
                } 
                else 
                {
                    // We *should* be looking at a quoted identifier name here. Some non-compliant JSON authors omit
                    // the wrapping quote marks, so we accommodate that case first.
                    string sName = null;

                    if (jtToken == JSONTokens.IMPLIED_IDENTIFIER_NAME)
                    {
                        sName = ParseUnquotedIdentifier(json, ref index, ref oErrors);
                        if (null == sName)
                        {
                            if (oErrors.iErrorIndex < 0) oErrors.iErrorIndex = index;
                            return null;
                        }
                    }
                    else
                    {
                        Debug.Assert(jtToken == JSONTokens.STRING, "Unexpected Token type; expecting String/Identifier");
                        sName = ParseString(json, ref index);
                        if (null == sName)
                        {
                            if (oErrors.iErrorIndex < 0) oErrors.iErrorIndex = index;
                            return null;
                        }
                    }

                    // Colon delimits the name from its value
                    jtToken = NextToken(json, ref index);
                    if (jtToken != JSONTokens.COLON)
                    {
                        if (oErrors.iErrorIndex < 0) oErrors.iErrorIndex = index;
                        return null;
                    }

                    // value
                    bool success = true;
                    object value = ParseValue(json, ref index, ref success, ref oErrors);
                    if (!success) 
                    {
                        Debug.Assert(false);
                        oErrors.iErrorIndex = index;
                        return null;
                    }

                    htThisObject[sName] = value;
                }
            }

            return htThisObject;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="json"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        private static ArrayList ParseArray(char[] json, ref int index, ref JSONParseErrors oErrors)
        {
            ArrayList alThisArray = new ArrayList();

            // [
            NextToken(json, ref index);

            bool done = false;
            while (!done) 
            {
                JSONTokens jtToken = LookAhead(json, index);
                if (jtToken == JSONTokens.NONE)
                {
                    if (oErrors.iErrorIndex < 0) oErrors.iErrorIndex = index;
                    return null;
                }
                else if (jtToken == JSONTokens.COMMA)
                {
                    NextToken(json, ref index);
                }
                else if (jtToken == JSONTokens.SQUARED_CLOSE)
                {
                    NextToken(json, ref index);
                    break;
                } 
                else 
                {
                    bool success = true;
                    object value = ParseValue(json, ref index, ref success, ref oErrors);
                    if (!success)
                    {
                        if (oErrors.iErrorIndex < 0) oErrors.iErrorIndex = index;
                        return null;
                    }

                    alThisArray.Add(value);
                }
            }

            return alThisArray;
        }

        private static object ParseValue(char[] json, ref int index, ref bool success, ref JSONParseErrors oErrors)
        {
            switch (LookAhead(json, index)) 
            {
                case JSONTokens.IMPLIED_IDENTIFIER_NAME:
                    return ParseUnquotedIdentifier(json, ref index, ref oErrors);

                case JSONTokens.STRING:
                    return ParseString(json, ref index);

                case JSONTokens.NUMBER:
                    return ParseNumber(json, ref index);

                case JSONTokens.CURLY_OPEN:
                    return ParseObject(json, ref index, ref oErrors);

                case JSONTokens.SQUARED_OPEN:
                    return ParseArray(json, ref index, ref oErrors);

                case JSONTokens.TRUE:
                    NextToken(json, ref index);
                    return true;

                case JSONTokens.FALSE:
                    NextToken(json, ref index);
                    return false;

                case JSONTokens.NULL:
                    NextToken(json, ref index);
                    return null;

                case JSONTokens.NONE:
                    break;
            }

            success = false;
            return null;
        }

        /// <summary>
        /// Similar to ParseString, but exits at the first whitespace or non-identifier character
        /// </summary>
        /// <param name="json"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        private static string ParseUnquotedIdentifier(char[] json, ref int index, ref JSONParseErrors oErrors)
        {
            EatWhitespace(json, ref index);

            int ixStart = index;
            StringBuilder s = new StringBuilder(BUILDER_DEFAULT_CAPACITY);
            char c;

            bool complete = false;
            while (!complete)
            {
                if (index == json.Length)
                {
                    break;
                }

                c = json[index];
                if (!isValidIdentifierChar(c))
                {
                    if (s.Length < 1) return null;
                    complete = true;
                    break;
                }
                else
                {
                    s.Append(c);
                }

                ++index;
            }

            if (!complete)
            {
                return null;
            }

            oErrors.sWarningText = string.Format("{0}Illegal/Unquoted identifier '{1}' at position {2}.\n", oErrors.sWarningText,
                s.ToString(),
                ixStart);

            return s.ToString();
        }

        private static string ParseString(char[] json, ref int index)
        {
            StringBuilder s = new StringBuilder(BUILDER_DEFAULT_CAPACITY);
            char c;

            EatWhitespace(json, ref index);
            
            // Eat the opening quote
            index++;

            bool complete = false;
            while (!complete) {

                if (index == json.Length) {
                    break;
                }

                c = json[index++];
                if (c == '"') {
                    complete = true;
                    break;
                } else if (c == '\\') {

                    if (index == json.Length) {
                        break;
                    }
                    c = json[index++];
                    if (c == '"') {
                        s.Append('"');
                    } else if (c == '\\') {
                        s.Append('\\');
                    } else if (c == '/') {
                        s.Append('/');
                    } else if (c == 'b') {
                        s.Append('\b');
                    } else if (c == 'f') {
                        s.Append('\f');
                    } else if (c == 'n') {
                        s.Append('\n');
                    } else if (c == 'r') {
                        s.Append('\r');
                    } else if (c == 't') {
                        s.Append('\t');
                    } else if (c == 'u') {
                        int remainingLength = json.Length - index;
                        if (remainingLength >= 4) {
                            uint codePoint = UInt32.Parse(new string(json, index, 4), NumberStyles.HexNumber);
                            // convert the integer codepoint to a unicode char and add to string

                            string sChar;
                            try
                            {
                                sChar = Char.ConvertFromUtf32((int)codePoint);
                            }
                            catch (Exception eX) 
                            {
                                Debug.WriteLine("JSONConvert failed: " + eX.Message);
                                // If character conversion fails, use the Unicode Replacement character.
                                sChar = "\uFFFD"; 
                            }

                            s.Append(sChar);
                            // skip 4 chars
                            index += 4;
                        } else {
                            break;
                        }
                    }
                } else {
                    s.Append(c);
                }

            }

            if (!complete) 
            {
                return null;
            }

            return s.ToString();
        }

        private static double ParseNumber(char[] json, ref int index)
        {
            EatWhitespace(json, ref index);

            int lastIndex = GetLastIndexOfNumber(json, index);
            int charLength = (lastIndex - index) + 1;

            string sNumber = new String(json, index, charLength);

            index = lastIndex + 1;
            return Double.Parse(sNumber, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets the character index of the end of the JavaScript number we're currently parsing.
        /// Numbers are tricky because of exponential notation, etc.
        /// </summary>
        /// <param name="json"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        private static int GetLastIndexOfNumber(char[] json, int index)
        {
            int lastIndex;
            for (lastIndex = index; lastIndex < json.Length; lastIndex++)
            {
                if ("0123456789+-.eE".IndexOf(json[lastIndex]) == -1)
                {
                    break;
                }
            }
            return lastIndex - 1;
        }

        private static void EatWhitespace(char[] json, ref int index)
        {
            for (; index < json.Length; index++) 
            {
                if (" \t\n\r".IndexOf(json[index]) == -1) 
                {
                    break;
                }
            }
        }

        private static JSONTokens LookAhead(char[] json, int index)
        {
            int saveIndex = index;
            return NextToken(json, ref saveIndex);
        }

        private static JSONTokens NextToken(char[] json, ref int index)
        {
            EatWhitespace(json, ref index);

            if (index == json.Length) 
            {
                return JSONTokens.NONE;
            }

            char c = json[index];
            ++index;
            switch (c)
            {
                case '{':
                    return JSONTokens.CURLY_OPEN;
                case '}':
                    return JSONTokens.CURLY_CLOSE;
                case '[':
                    return JSONTokens.SQUARED_OPEN;
                case ']':
                    return JSONTokens.SQUARED_CLOSE;
                case ',':
                    return JSONTokens.COMMA;
                case '"':
                    return JSONTokens.STRING;
                case '0': case '1': case '2': case '3': case '4': 
                case '5': case '6': case '7': case '8': case '9':
                case '-':
                    return JSONTokens.NUMBER;
                case ':':
                    return JSONTokens.COLON;
            }
            --index;

            int remainingLength = json.Length - index;

            if (remainingLength >= 5) {
                if (json[index] == 'f' &&
                    json[index + 1] == 'a' &&
                    json[index + 2] == 'l' &&
                    json[index + 3] == 's' &&
                    json[index + 4] == 'e') 
                {
                    index += 5;
                    return JSONTokens.FALSE;
                }
            }

            if (remainingLength >= 4) {
                if (json[index] == 't' &&
                    json[index + 1] == 'r' &&
                    json[index + 2] == 'u' &&
                    json[index + 3] == 'e') 
                {
                    index += 4;
                    return JSONTokens.TRUE;
                }
            }

            if (remainingLength >= 4) 
            {
                if (json[index] == 'n' &&
                    json[index + 1] == 'u' &&
                    json[index + 2] == 'l' &&
                    json[index + 3] == 'l') 
                {
                    index += 4;
                    return JSONTokens.NULL;
                }
            }

            //
            // At this point, we can check to see if this is a simple ASCII text string and
            // if so, return JSON.TOKEN_IMPLIED_IDENTIFIER which basically behaves like JSON.TOKEN_STRING
            //
            if (isValidIdentifierStart(json[index]))
            {
                return JSONTokens.IMPLIED_IDENTIFIER_NAME;
            }

            return JSONTokens.NONE;
        }

        /// <summary>
        /// Returns TRUE if this character might be the valid start of a JavaScript variable identifier
        /// </summary>
        /// <remarks>
        /// TODO: See http://stackoverflow.com/questions/1661197/valid-characters-for-javascript-variable-names to see how
        /// this method doesn't account for all valid variable names, just the most reasonable ones</remarks>
        /// <param name="c">The character to test</param>
        /// <returns>TRUE if the character may start a JavaScript identifier</returns>
        private static bool isValidIdentifierStart(char c)
        {
            if ((c == '_') || (c == '$')) return true;
            if ((c == '\'')) return true;           // Single-quoting on variable names is illegal but we WARN
            if (char.IsLetter(c)) return true;
            return false;
        }

        /// <summary>
        /// Returns TRUE if this character may validly appear within a JavaScript variable identifier. 
        /// TODO: See comment on isValidIdentifierStart() for details about how this is incomplete
        /// </summary>
        /// <param name="c">The character to test</param>
        /// <returns>TRUE if the character may appear within a JavaScript identifier</returns>
        private static bool isValidIdentifierChar(char c)
        {
            if ((c == '-') || (c == '_') || (c == '$')) return true;
            if (char.IsLetterOrDigit(c)) return true;
            if ((c == '\'')) return true;           // Single-quoting on variable names is illegal but we WARN
            return false;
        }

        /// <summary>
        /// Converts an IDictionary or IList object graph into a JSON string
        /// </summary>
        /// <param name="json">A Hashtable or ArrayList</param>
        /// <returns>A JSON encoded string, or null if object 'json' is not serializable</returns>
        public static string JsonEncode(object json)
        {
            StringBuilder builder = new StringBuilder(BUILDER_DEFAULT_CAPACITY);
            bool success = JSON.SerializeValue(json, builder);
            return (success ? builder.ToString() : null);
        }

        private static bool SerializeObject(IDictionary anObject, StringBuilder builder)
        {
            builder.Append("{");

            IDictionaryEnumerator e = anObject.GetEnumerator();
            bool first = true;
            while (e.MoveNext()) 
            {
                string key = e.Key.ToString();
                object value = e.Value;

                if (!first) {
                    builder.Append(", ");
                }

                SerializeString(key, builder);
                builder.Append(":");
                if (!SerializeValue(value, builder)) 
                {
                    return false;
                }

                first = false;
            }

            builder.Append("}");
            return true;
        }

        private static bool SerializeArray(IList anArray, StringBuilder builder)
        {
            builder.Append("[");

            bool first = true;
            for (int i = 0; i < anArray.Count; i++) 
            {
                object value = anArray[i];

                if (!first) 
                {
                    builder.Append(", ");
                }

                if (!SerializeValue(value, builder)) 
                {
                    return false;
                }

                first = false;
            }

            builder.Append("]");
            return true;
        }

        private static bool SerializeValue(object value, StringBuilder builder)
        {
            if (null == value) 
            { 
                builder.Append("null");
            } else if (value is string) {
                SerializeString((string)value, builder);
            } else if (value is Hashtable) {
                SerializeObject((Hashtable)value, builder);
            } else if (value is ArrayList) {
                SerializeArray((ArrayList)value, builder);
            } else if (IsNumeric(value)) {
                SerializeNumber(Convert.ToDouble(value), builder);
            } else if ((value is Boolean) && ((Boolean)value == true)) {
                builder.Append("true");
            } else if ((value is Boolean) && ((Boolean)value == false)) {
                builder.Append("false");
            } 
            else 
            {
                return false;
            }
            return true;
        }

        private static void SerializeString(string aString, StringBuilder builder)
        {
            builder.Append("\"");

            char[] charArray = aString.ToCharArray();
            for (int i = 0; i < charArray.Length; i++) 
            {
                switch(charArray[i])
                {
                    case '"':
                        builder.Append("\\\"");
                        break;
                    case '\\':
                        builder.Append(@"\\");
                        break;

                    case '\b':
                        builder.Append(@"\b");
                        break;

                    case '\f':
                        builder.Append(@"\f");
                        break;

                    case '\n':
                        builder.Append(@"\n");
                        break;

                    case '\r':
                        builder.Append(@"\r");
                        break;

                    case '\t':
                        builder.Append(@"\t");
                        break;

                    default:
                        char c = charArray[i];
                        int codepoint = Convert.ToInt32(c);
                        if ((codepoint >= 32) && (codepoint <= 126)) 
                        {
                            builder.Append(c);
                        } 
                        else 
                        {
                            builder.Append("\\u" + codepoint.ToString("x").PadLeft(4, '0'));
                        }
                    break;
                }
            }
            builder.Append("\"");
        }

        private static void SerializeNumber(double number, StringBuilder builder)
        {
            builder.Append(Convert.ToString(number, CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Determines if a given object is numeric in any way
        /// </summary>
        private static bool IsNumeric(object o)
        {
            try
            {
                Double.Parse(o.ToString());
            } 
            catch (Exception) 
            {
                return false;
            }
            return true;
        }
    }
}