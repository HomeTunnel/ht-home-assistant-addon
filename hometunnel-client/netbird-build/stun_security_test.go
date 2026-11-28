package stun
import ("testing"; "io")
func TestHomeTunnelShortXORAddress(t *testing.T) {
 for n:=0; n<=4; n++ { m:=new(Message); m.Add(AttrXORMappedAddress, make([]byte,n)); var a XORMappedAddress; if err:=a.GetFrom(m); err!=io.ErrUnexpectedEOF {t.Fatalf("length %d: %v",n,err)} }
}
