package ctap

// Optional capability, so backends without a verification policy continue to
// omit UV from GetInfo. A false result must never produce a signed assertion.
type userVerifier interface {
	SupportsUserVerification() bool
	VerifyUser(relyingPartyID string) bool
}

func (server *CTAPServer) supportsUserVerification() bool {
	verifier, ok := server.client.(userVerifier)
	return ok && verifier.SupportsUserVerification()
}

func (server *CTAPServer) verifyUser(relyingPartyID string) ctapStatusCode {
	if !server.supportsUserVerification() {
		return ctap2ErrUnsupportedOption
	}
	if !server.client.(userVerifier).VerifyUser(relyingPartyID) {
		return ctap2ErrOperationDenied
	}
	return ctap1ErrSuccess
}
