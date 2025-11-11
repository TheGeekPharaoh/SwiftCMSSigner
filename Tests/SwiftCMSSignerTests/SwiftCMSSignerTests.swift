import Testing
import XCTest
@testable import SwiftCMSSigner

@Test func example() async throws {
    // Write your test here and use APIs like `#expect(...)` to check expected conditions.
}

final class SwiftCMSSignerTests: XCTestCase {
    
    func testCreateCMSSignedMessageBase64() {
        // A simple test message that we’ll sign using our CMS signer
        // You can replace this with any sample data you like
        let message = "Hello, CMS!"
        guard let messageData = message.data(using: .utf8) else {
            XCTFail("Failed to encode message to Data")
            return
        }

        // Replace with actual PEM values (certificate and key) for testing
        // These are placeholder PEM blocks for the test
        let testCertificatePEM = """
        -----BEGIN CERTIFICATE-----
        MIID/TCCAuWgAwIBAgIUJILtdXPQwgXKjvW18/mKxOnormkwDQYJKoZIhvcNAQEL
        BQAwgY0xCzAJBgNVBAYTAklSMQ8wDQYDVQQIDAZUZWhyYW4xDzANBgNVBAcMBnRl
        aHJhbjEMMAoGA1UECgwDR1NTMRAwDgYDVQQLDAdiYWNrZW5kMRIwEAYDVQQDDAlk
        ZXZlbG9wZXIxKDAmBgkqhkiG9w0BCQEWGWphdmFoZXJpbWhtZGFsaUBnbWFpbC5j
        b20wHhcNMjUwNTIwMTAyMjI1WhcNMjYwNTIwMTAyMjI1WjCBjTELMAkGA1UEBhMC
        SVIxDzANBgNVBAgMBlRlaHJhbjEPMA0GA1UEBwwGdGVocmFuMQwwCgYDVQQKDANH
        U1MxEDAOBgNVBAsMB2JhY2tlbmQxEjAQBgNVBAMMCWRldmVsb3BlcjEoMCYGCSqG
        SIb3DQEJARYZamF2YWhlcmltaG1kYWxpQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcN
        AQEBBQADggEPADCCAQoCggEBAKXqNmyGwH9ZabVD7UdRL6Z3HetbmD0iicGHaoes
        SC0L3E4g4E6ZWmqBHI04oRbYK4V+b+ZNBcREZllwTQqfYV+y/ES4dJtN3sn82QCO
        W7Tdeqz6PKzteDCdp4WXPwSHGKQgZluTAO+rjbv5b1LpXoyK5sEgs/aDFgnebV6J
        st7eDl9zSP6g0pN7wjq25gE+HE7o0oJ3nyfY5n3SrV4/a3WoVxDLmp4i8bCLzDdH
        TGaxIGKHkxktf2whfp20DsLVE+3A/y+Sa2Mrrr3YuYWdVQZVbqrk2QNcULJW/I9D
        S5lUNRwWiudid3g4skoGQuXKywsVxNx1dtil5g+4JolDdCUCAwEAAaNTMFEwHQYD
        VR0OBBYEFAVMHG2WjZc8WfeZKYBGTp2eDeY0MB8GA1UdIwQYMBaAFAVMHG2WjZc8
        WfeZKYBGTp2eDeY0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
        AEg4yi5Tnzm4+79jKutHIhci+b2CXXfX9T2gBX2rF57wqkWTYHguipy9NWR6Szqx
        0uopBQrzlGinWUZgVQiy+oD7XoIhJIINRY8ujCR/vDxcQOnO6BP+pDq0v5ZwtLRk
        MzJCQbyTG7B1k5yuGGjWqfH2HcJgx+HaqNzbH251+wM6Ckwtw/0vHdu6pyoyxbsE
        ZAHU5+f3Om3c5NcBQYFXHAuMUkZVpt1SYhAgqWVnOlIyebBLyXZOVSuCG3yruPbJ
        yOyh2PfxSRggwHh4Q49Erokgfmf5ei3wvNlHB6BhLtF1kHd6qVTKqb44PgN1lgnJ
        1yN+Vm99K8oq1NIC734LcAo=
        -----END CERTIFICATE-----
        """

        let testPrivateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl6jZshsB/WWm1
        Q+1HUS+mdx3rW5g9IonBh2qHrEgtC9xOIOBOmVpqgRyNOKEW2CuFfm/mTQXERGZZ
        cE0Kn2FfsvxEuHSbTd7J/NkAjlu03Xqs+jys7XgwnaeFlz8EhxikIGZbkwDvq427
        +W9S6V6MiubBILP2gxYJ3m1eibLe3g5fc0j+oNKTe8I6tuYBPhxO6NKCd58n2OZ9
        0q1eP2t1qFcQy5qeIvGwi8w3R0xmsSBih5MZLX9sIX6dtA7C1RPtwP8vkmtjK669
        2LmFnVUGVW6q5NkDXFCyVvyPQ0uZVDUcFornYnd4OLJKBkLlyssLFcTcdXbYpeYP
        uCaJQ3QlAgMBAAECggEAEL4D7GsjoSYvZ9J5LuVnIsvp2b5mLCMgVgZZbmPo65zD
        CCJCqEPKzy0Eqc6BWOoK6D9kQM/caVwCnPtbVttS6uKHmNKpN6PBu823QxpacDOa
        RbrBpSyYYIWEKlOjEQyl5Kf9VDfPFCBSXtnSjUIN365Dj1ECv/kl3+yRSkUoZttF
        MvkSmxhRVjOUaLgo7Jg6ZkGKJLh9iAnwckSV30kxnqRjJ6SH/XJ/fnIRPfa4rgT4
        GOWTQhJFJObZnhdH5OviNz670UFeNbaeeyhtNhVN7trEXVH53fr1m32t+C7FPD7r
        usOTXKBuu8mLUJSWxLSaXufPx+Ztv2XNN4PEeoOucQKBgQC5lPcZ9JkMRlihAYQC
        xSTBc+nsJEWsI1IhrdRo8d9CwXcpvZdYexcerz5oMKy/E30/x65UEuXGYnfx5JKQ
        xQsgQFVGpaX5tpsGgA2dlpRFjMxjA8UyAwAMpkGFHngiZNOu9W9oXnV74JaZlQtU
        dsgwzUABqlwuxubHddcmOzk6cQKBgQDk3tYL3VA7poM2vBW5QN+0vba9A/JllEwQ
        vn64trJTMdNe7lF4Pq+KnofsQ9g4sf0HvIKWZbqJ2mNCzvKsO4VVMWorhxmrJVZ1
        Z3pnSth6gwplkECJ/9+ikdXx2PQPuTa71berQFep6j/RL2KuM7sDyNOT7CG28SQZ
        qbi+LU3m9QKBgGO0XtW5DgkEOlW2RMBgPpEYv5K5Ih2LlHK3u6juWe65llX8oDVP
        XGqF6Fd93zGBPQdpNoXA6WYePSbekMfqtUGMjsQ39uYkb0GcxrPl1J9RN/Xybp2h
        8wLYx9bHOe/wj7It9r7yENiPHxpAcyfb8U4W186NQp13C0IaU48cvnBhAoGBAJxg
        DMuqeSloifqZ5BXhV3f8r6DR04rIGnjOT3MRkSH6xzrzhkKsQfBqhOBPMqr6IbJp
        gKgV9bA+wNdi4rf/KwicbLg05LrlFf+9pgpxPxvl8PKX7yDa7Qf8sLs/yvH7UIRi
        b83Ydo0n+laJE9mGit75FmbZTefbNxk5t3ppJfMJAoGAPqpAW9bSN3FmwRNwpmKU
        EYRrAAZknQTiwPo5g5bG/ZsAwB/iso5Lm90v5CMmYml7fCuciTo44iIlcRG/QEjJ
        onIWMmT79RF0xs19xjHnyAh7A0CtnWqSDYMJa7YVM5Y847B4xrU9Jwo2HYBh2qh/
        mUp+sUSZW5PuHXwShOV6WCs=
        -----END PRIVATE KEY-----
        """

        let signer = SwiftCMSSigner()
        let base64CMSDetached = signer.createCMSSignedMessageBase64(
            inputData: messageData,
            certPEM: testCertificatePEM,
            keyPEM: testPrivateKeyPEM,
			detached: true
        )

        XCTAssertNotNil(base64CMSDetached, "CMS signed message should not be nil")
        XCTAssertFalse(base64CMSDetached!.isEmpty, "CMS signed message should not be empty")
        print("CMS Base64 Output (detached): \(base64CMSDetached!)")

		let base64CMSAttached = signer.createCMSSignedMessageBase64(
			inputData: messageData,
			certPEM: testCertificatePEM,
			keyPEM: testPrivateKeyPEM,
			detached: false
		)

		XCTAssertNotNil(base64CMSAttached, "CMS signed message should not be nil")
		XCTAssertFalse(base64CMSAttached!.isEmpty, "CMS signed message should not be empty")
		XCTAssertNotEqual(base64CMSAttached, base64CMSDetached)
		print("CMS Base64 Output (attached): \(base64CMSAttached!)")
}
}
