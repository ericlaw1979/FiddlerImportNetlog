# FiddlerImportNetlog

I wrote a [Blog Post](https://www.telerik.com/blogs/building-fiddler-importers) that explains this extension.

It allows you to import [Chromium NetLog](https://www.chromium.org/developers/design-documents/network-stack/netlog) traffic captures into Fiddler.

Note that the NetLog format is somewhat lossy (e.g. request body bytes are never included, and credentials and response bodies *may* be excluded) so full-fidelity import is not generally possible.

If you'd just like to add this importer without building it yourself, you can [Download it from the Releases page](https://github.com/ericlaw1979/FiddlerImportNetlog/releases/)
