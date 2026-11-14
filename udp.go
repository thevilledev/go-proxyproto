package proxyproto

import (
	"bufio"
	"bytes"
)

// ParseUDPDatagram parses a PROXY protocol header at the start of a UDP
// datagram and returns the header together with the proxied payload that
// follows it. The returned payload aliases the datagram slice.
//
// Per spec (section 2), when the PROXY protocol is carried over UDP the header
// and the proxied payload MUST be sent in the same datagram, and the receiver
// MUST parse the header independently for each received datagram. Call this
// for every datagram received; there is no connection state to carry over.
// Conn and Listener are stream-oriented and cannot provide those semantics.
//
// A datagram that does not begin with a complete, valid header fails with the
// same errors Read returns — ErrNoProxyProtocol when the signature is absent.
// The spec forbids guessing whether a header is present, so on a receiver
// configured for the PROXY protocol such datagrams must be dropped, not
// treated as raw payload.
func ParseUDPDatagram(datagram []byte) (*Header, []byte, error) {
	byteReader := bytes.NewReader(datagram)
	// The payload is returned directly from datagram, so buffering all of it
	// would allocate and copy it unnecessarily. readBufferSize holds a whole
	// v1 header (at most 107 bytes), as required by its single-read parser.
	// v2 can read larger headers in chunks from byteReader.
	reader := bufio.NewReaderSize(byteReader, min(len(datagram), readBufferSize))
	header, err := Read(reader)
	if err != nil {
		return nil, nil, err
	}
	// Unread bytes may be buffered or still waiting in byteReader.
	consumed := len(datagram) - reader.Buffered() - byteReader.Len()
	return header, datagram[consumed:], nil
}

// FormatUDPDatagram renders the header followed by the proxied payload,
// producing the exact bytes to send as one UDP datagram. Per spec (section 2)
// the header and the payload MUST share a single datagram, which a single
// write of the returned slice guarantees; formatting the header and payload
// separately risks a sender splitting them across datagrams.
func (header *Header) FormatUDPDatagram(payload []byte) ([]byte, error) {
	buf, err := header.Format()
	if err != nil {
		return nil, err
	}
	return append(buf, payload...), nil
}
