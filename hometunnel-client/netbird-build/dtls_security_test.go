package ciphersuite
import ("testing"; "bytes"; "encoding/binary"; "github.com/pion/dtls/v2/pkg/protocol"; "github.com/pion/dtls/v2/pkg/protocol/recordlayer")
func TestHomeTunnelUniqueGCMNonce(t *testing.T) {
 key:=make([]byte,16); iv:=make([]byte,4); g,err:=NewGCM(key,iv,key,iv); if err!=nil {t.Fatal(err)}
 seen:=map[uint64]bool{}
 for _,pair:=range [][2]uint64{{1,0},{1,1},{2,0},{2,0xffffffffffff}} {
 payload:=[]byte("synthetic payload")
 pkt:= &recordlayer.RecordLayer{Header:recordlayer.Header{ContentType:protocol.ContentTypeApplicationData,Version:protocol.Version1_2,Epoch:uint16(pair[0]),SequenceNumber:pair[1],ContentLen:uint16(len(payload))}}
 header,err:=pkt.Header.Marshal(); if err!=nil {t.Fatal(err)}
 encrypted,err:=g.Encrypt(pkt,append(header,payload...)); if err!=nil {t.Fatal(err)}
 nonce:=binary.BigEndian.Uint64(encrypted[recordlayer.HeaderSize:recordlayer.HeaderSize+8]); expected:=pair[0]<<48|pair[1]
 if nonce!=expected || seen[nonce] {t.Fatalf("nonce mismatch or reuse: %x",nonce)}; seen[nonce]=true
 plain,err:=g.Decrypt(encrypted); if err!=nil {t.Fatal(err)}; if !bytes.Equal(plain[recordlayer.HeaderSize:],payload) {t.Fatal("roundtrip failed")}
 }
}
