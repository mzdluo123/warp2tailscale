//go:build !mvptest

package main

import (
	"context"

	"tailscale.com/tsnet"
)

func watchTestCC(context.Context, *tsnet.Server) {}
