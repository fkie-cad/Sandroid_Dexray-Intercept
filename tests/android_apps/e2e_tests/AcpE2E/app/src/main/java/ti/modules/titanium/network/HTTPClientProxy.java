package ti.modules.titanium.network;

/**
 * Minimal stub of Titanium's HTTPClientProxy for PinningTrustManager.
 * Only methods used by PinningTrustManager are provided.
 */
public class HTTPClientProxy {

    public HTTPClientProxy() {
    }

    public boolean getValidatesSecureCertificate() {
        // Simulate default behaviour where secure certificates are validated.
        return true;
    }

    public String getLocation() {
        // Return dummy HTTPS URL for host parsing in PinningTrustManager.
        return "https://example.com/path";
    }
}