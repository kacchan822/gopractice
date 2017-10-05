package certlimit

import (
	"crypto/tls"
	"fmt"
	"time"
)

// CertLimit SSL証明書の有効期限をチェックする。
// 有効期限の開始日、終了日、残り日数を返す。
func CertLimit(host string, port int) (time.Time, time.Time, int64) {

	config := &tls.Config{InsecureSkipVerify: false}
	conn, _ := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	now := time.Now()
	duration := int64(certs[0].NotAfter.Sub(now).Hours() / 24)

	defer conn.Close()

	return certs[0].NotBefore, certs[0].NotAfter, duration
}
