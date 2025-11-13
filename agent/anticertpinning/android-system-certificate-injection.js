/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does so by attaching to the internals of Conscrypt (the Android SDK's standard
 * TLS implementation) and pre-adding our certificate to the 'already trusted' cache, so that
 * future connections trust it implicitly. This ensures that all normal uses of Android APIs
 * for HTTPS & TLS will allow interception.
 *
 * This does not handle all standalone certificate pinning techniques - where the application
 * actively rejects certificates that are trusted by default on the system. That's dealt with
 * in the separate certificate unpinning script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/
import {PROXY_HOST, PROXY_PORT, CERT_PEM, DEBUG_MODE, IGNORED_NON_HTTP_PORTS, BLOCK_HTTP3, PROXY_SUPPORTS_SOCKS5, CERT_DER, MODULE_LOAD_CALLBACKS} from "./config_custom.js"
import Java from "frida-java-bridge";

export function androidSystemCertInjection(){
    Java.perform(() => {
        // First, we build a JVM representation of our certificate:
        const String = Java.use("java.lang.String");
        const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
        const CertFactory = Java.use('java.security.cert.CertificateFactory');

        let cert;
        try {
            const certFactory = CertFactory.getInstance("X.509");
            const certBytes = String.$new(CERT_PEM).getBytes();
            cert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
        } catch (e) {
            if (DEBUG_MODE) console.log('[!] ACP: Could not parse provided certificate PEM!');
            if (DEBUG_MODE) console.log(`[!] ACP: ${e}`);
            Java.use('java.lang.System').exit(1);
        }

        // Then we hook TrustedCertificateIndex. This is used for caching known trusted certs within Conscrypt -
        // by prepopulating all instances, we ensure that all TrustManagerImpls (and potentially other
        // things) automatically trust our certificate specifically (without disabling validation entirely).
        // This should apply to Android v7+ - previous versions used SSLContext & X509TrustManager.
        [
            'com.android.org.conscrypt.TrustedCertificateIndex',
            'org.conscrypt.TrustedCertificateIndex', // Might be used (com.android is synthetic) - unclear
            'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex' // Used in Apache Harmony version of Conscrypt
        ].forEach((TrustedCertificateIndexClassname, i) => {
            let TrustedCertificateIndex;
            try {
                TrustedCertificateIndex = Java.use(TrustedCertificateIndexClassname);
            } catch (e) {
                if (i === 0) {
                    throw new Error(`${TrustedCertificateIndexClassname} not found - could not inject system certificate`);
                } else {
                    // Other classnames are optional fallbacks
                    if (DEBUG_MODE) {
                        console.log(`[*] ACP: [ ] Skipped cert injection for ${TrustedCertificateIndexClassname} (not present)`);
                    }
                    return;
                }
            }

            TrustedCertificateIndex.$init.overloads.forEach((overload) => {
                overload.implementation = function () {
                    this.$init(...arguments);
                    // Index our cert as already trusted, right from the start:
                    this.index(cert);
                }
            });

            TrustedCertificateIndex.reset.overloads.forEach((overload) => {
                overload.implementation = function () {
                    const result = this.reset(...arguments);
                    // Index our cert in here again, since the reset removes it:
                    this.index(cert);
                    return result;
                };
            });

            if (DEBUG_MODE) console.log(`[+] ACP: Injected cert into ${TrustedCertificateIndexClassname}`);
        });

        // There was a problem, that sometimes the cert was not injected.
        // The error messages indicate, that the "checkTrustedRecursive" in the class "com.android.org.conscrypt.TrustManagerImpl" fails.
        // Probably same as this PR: https://github.com/httptoolkit/frida-interception-and-unpinning/pull/101
        // Therefore we need to take care of that as well.

        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl")
        TrustManagerImpl.checkTrustedRecursive.implementation = function(x509certs, n0, n1, host, b, al1, al2, s){return al1} // this is pretty aggressive

        // This effectively adds us to the system certs, and also defeats quite a bit of basic certificate
        // pinning too! It auto-trusts us in any implementation that uses TrustManagerImpl (Conscrypt) as
        // the underlying cert checking component.

        if (DEBUG_MODE) console.log('[*] ACP: System certificate trust injected');
    });
}