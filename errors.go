package securecookie

import "strings"

// Error is the interface of all errors returned by functions in this library.
type Error interface {
	error

	// IsUsage returns true for errors indicating the client code probably
	// uses this library incorrectly.  For example, the client may have
	// failed to provide a valid hash key, or may have failed to configure
	// the Serializer adequately for encoding value.
	IsUsage() bool

	// IsDecode returns true for errors indicating that a cookie could not
	// be decoded and validated.  Since cookies are usually untrusted
	// user-provided input, errors of this type should be expected.
	// Usually, the proper action is simply to reject the request.
	IsDecode() bool

	// IsInternal returns true for unexpected errors occurring in the
	// securecookie implementation.
	IsInternal() bool

	// Cause, if it returns a non-nil value, indicates that this error was
	// propagated from some underlying library.  If this method returns nil,
	// this error was raised directly by this library.
	//
	// Cause is provided principally for debugging/logging purposes; it is
	// rare that application logic should perform meaningfully different
	// logic based on Cause.  See, for example, the caveats described on
	// (MultiError).Cause().
	Cause() error
}

// errorType is a bitmask giving the error type(s) of an cookieError value.
type errorType int

const (
	usageError = errorType(1 << iota)
	decodeError
	internalError
)

type cookieError struct {
	typ   errorType
	msg   string
	cause error
}

func (e cookieError) IsUsage() bool    { return (e.typ & usageError) != 0 }
func (e cookieError) IsDecode() bool   { return (e.typ & decodeError) != 0 }
func (e cookieError) IsInternal() bool { return (e.typ & internalError) != 0 }

func (e cookieError) Cause() error { return e.cause }

func (e cookieError) Error() string {
	parts := []string{"securecookie: "}
	if e.msg == "" {
		parts = append(parts, "error")
	} else {
		parts = append(parts, e.msg)
	}
	if c := e.Cause(); c != nil {
		parts = append(parts, " - caused by: ", c.Error())
	}
	return strings.Join(parts, "")
}

var (
	errGeneratingIV = cookieError{typ: internalError, msg: "failed to generate random iv"}

	errNoCodecs            = cookieError{typ: usageError, msg: "no codecs provided"}
	errHashKeyNotSet       = cookieError{typ: usageError, msg: "hash key is not set"}
	errBlockKeyNotSet      = cookieError{typ: usageError, msg: "block key is not set"}
	errEncodedValueTooLong = cookieError{typ: usageError, msg: "the value is too long"}

	errValueToDecodeTooLong = cookieError{typ: decodeError, msg: "the value is too long"}
	errTimestampInvalid     = cookieError{typ: decodeError, msg: "invalid timestamp"}
	errTimestampTooNew      = cookieError{typ: decodeError, msg: "timestamp is too new"}
	errTimestampExpired     = cookieError{typ: decodeError, msg: "expired timestamp"}
	errDecryptionFailed     = cookieError{typ: decodeError, msg: "the value could not be decrypted"}
	errValueNotByte         = cookieError{typ: decodeError, msg: "value not a []byte."}

	// ErrMacInvalid indicates that cookie decoding failed because the HMAC
	// could not be extracted and verified.  Direct use of this error
	// variable is deprecated; it is public only for legacy compatibility,
	// and may be privatized in the future, as it is rarely useful to
	// distinguish between this error and other Error implementations.
	ErrMacInvalid = cookieError{typ: decodeError, msg: "the value is not valid"}
)
