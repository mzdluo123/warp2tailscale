//go:build mvptest

package tsnet

func (s *Server) SetTestExitCC(cc string) error { return s.netstack.SetExitCC(cc) }
