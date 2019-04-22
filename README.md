# FiddlerImportNetlog

Import [Chromium NetLog](https://www.chromium.org/developers/design-documents/network-stack/netlog) log files into Fiddler.

The NetLog format is somewhat lossy (e.g. request body bytes are never included, and credentials and response bodies *may* be excluded) so full-fidelity import is not generally possible.