package nfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// RPC Constants
const (
	RPCVersion = 2
	// MountProg        = 100005 //defined in mount.go
	MountVers3      = 3
	MountProcExport = 5
	PmapProg        = 100000
	PmapVers        = 2
	PmapProcGetPort = 3
	IPProtoTCP      = 6
)

// ExportEntry represents one exported directory and its allowed clients
type ExportEntry struct {
	Dir    string
	Groups []string
}

// GetExports connects to the NFS server's mount daemon and retrieves the export list.
func GetExports(host string) ([]ExportEntry, error) {
	// 1. Find the MOUNTD port using Portmapper
	mountPort, err := getMountPort(host)
	if err != nil {
		return nil, fmt.Errorf("failed to get mount port: %v", err)
	}

	// 2. Connect to MOUNTD
	address := fmt.Sprintf("%s:%d", host, mountPort)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial mountd: %v", err)
	}
	defer conn.Close()

	// 3. Send EXPORT Request (RPC Header only, no arguments)
	// XID, MsgType, RPCVers, Prog, Vers, Proc, Auth(Null), Verif(Null)
	req := &bytes.Buffer{}
	xid := uint32(time.Now().UnixNano())

	// We build the RPC header manually to avoid internal library dependencies
	binary.Write(req, binary.BigEndian, xid)       // XID
	binary.Write(req, binary.BigEndian, uint32(0)) // MsgType: CALL
	binary.Write(req, binary.BigEndian, uint32(2)) // RPC Version: 2
	binary.Write(req, binary.BigEndian, uint32(MountProg))
	binary.Write(req, binary.BigEndian, uint32(MountVers3))
	binary.Write(req, binary.BigEndian, uint32(MountProcExport))

	// Auth Null
	binary.Write(req, binary.BigEndian, uint32(0)) // Flavor: AUTH_NULL
	binary.Write(req, binary.BigEndian, uint32(0)) // Length: 0
	// Verifier Null
	binary.Write(req, binary.BigEndian, uint32(0)) // Flavor: AUTH_NULL
	binary.Write(req, binary.BigEndian, uint32(0)) // Length: 0

	// Send Packet (Fragmented for TCP)
	// RFC 1057: Record Marking Standard. Last fragment bit (1<<31) | length
	packet := req.Bytes()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet))|0x80000000)

	conn.Write(header)
	conn.Write(packet)

	// 4. Read Response
	// Read Fragment Header
	respHeader := make([]byte, 4)
	if _, err := conn.Read(respHeader); err != nil {
		return nil, err
	}
	// Read Body
	length := binary.BigEndian.Uint32(respHeader) & 0x7fffffff
	respData := make([]byte, length)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, err
	}

	return parseExportList(respData)
}

func parseExportList(data []byte) ([]ExportEntry, error) {
	buf := bytes.NewReader(data)

	// Skip RPC Reply Header (XID, MsgType, ReplyState, Verifier, AcceptState)
	// This is a simplified skip. In production, check XID and Status.
	// XID (4) + Type (4) + ReplyState (4) + Verifier (8) + AcceptState (4) = 24 bytes generic success
	buf.Seek(24, io.SeekCurrent)

	var exports []ExportEntry

	// Read Exports Linked List
	// struct exportnode { dir, groups, next }
	for {
		var valueFollows uint32
		if err := binary.Read(buf, binary.BigEndian, &valueFollows); err != nil {
			break
		}
		if valueFollows == 0 {
			break
		}

		// Read Directory
		dir, err := readXDRString(buf)
		if err != nil {
			return nil, err
		}

		// Read Groups Linked List
		var groups []string
		for {
			var grpValueFollows uint32
			binary.Read(buf, binary.BigEndian, &grpValueFollows)
			if grpValueFollows == 0 {
				break
			}
			grp, err := readXDRString(buf)
			if err == nil {
				groups = append(groups, grp)
			}
		}

		exports = append(exports, ExportEntry{Dir: dir, Groups: groups})
	}

	return exports, nil
}

func readXDRString(r *bytes.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		return "", err
	}
	// XDR padding: 4 byte alignment
	pad := (4 - (length % 4)) % 4
	r.Seek(int64(pad), io.SeekCurrent)
	return string(out), nil
}

func getMountPort(host string) (int, error) {
	// Connect to Portmapper (TCP 111)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "111"), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// PMAPPROC_GETPORT Call
	// Args: Prog, Vers, Proto, Port(0)
	req := &bytes.Buffer{}
	xid := uint32(time.Now().UnixNano())

	binary.Write(req, binary.BigEndian, xid)
	binary.Write(req, binary.BigEndian, uint32(0)) // Call
	binary.Write(req, binary.BigEndian, uint32(2)) // RPC Vers
	binary.Write(req, binary.BigEndian, uint32(PmapProg))
	binary.Write(req, binary.BigEndian, uint32(PmapVers))
	binary.Write(req, binary.BigEndian, uint32(PmapProcGetPort))
	binary.Write(req, binary.BigEndian, uint32(0)) // Auth Null
	binary.Write(req, binary.BigEndian, uint32(0))
	binary.Write(req, binary.BigEndian, uint32(0)) // Verif Null
	binary.Write(req, binary.BigEndian, uint32(0))

	// PMAP Args
	binary.Write(req, binary.BigEndian, uint32(MountProg))
	binary.Write(req, binary.BigEndian, uint32(MountVers3))
	binary.Write(req, binary.BigEndian, uint32(IPProtoTCP))
	binary.Write(req, binary.BigEndian, uint32(0))

	// Send
	packet := req.Bytes()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet))|0x80000000)
	conn.Write(header)
	conn.Write(packet)

	// Read
	respHeader := make([]byte, 4)
	conn.Read(respHeader)
	length := binary.BigEndian.Uint32(respHeader) & 0x7fffffff
	respData := make([]byte, length)
	io.ReadFull(conn, respData)

	buf := bytes.NewReader(respData)
	buf.Seek(24, io.SeekCurrent) // Skip RPC Header
	var port uint32
	binary.Read(buf, binary.BigEndian, &port)

	if port == 0 {
		return 0, fmt.Errorf("mount service not registered")
	}
	return int(port), nil
}
