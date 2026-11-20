package policy

import (
	"net/netip"

	"github.com/Diniboy1123/usque/bridge/destination"
)

func Allowed(dst netip.AddrPort) bool { return destination.Allowed(dst) }
