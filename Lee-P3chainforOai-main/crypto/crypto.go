package crypto

import (
	// "github.com/ethereum/go-ethereum/crypto"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"p3Chain/common"
	"p3Chain/crypto/ecies"
	"p3Chain/crypto/secp256k1"
	"p3Chain/crypto/sha3"
	// "p3Chain/crypto"
)

// ========================= 变色龙哈希实现 ==============================

// type MyCurve struct {
// 	*elliptic.CurveParams
// }

// var Secp256k1 = &MyCurve{
//     CurveParams: &elliptic.CurveParams{
//         Name:    "secp256k1",
//         P:       hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
//         N:       hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
//         B:       hexToBigInt("0000000000000000000000000000000000000000000000000000000000000007"),
//         Gx:      hexToBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
//         Gy:      hexToBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
//         BitSize: 256,
//     },
// }

// func hexToBigInt(hex string) *big.Int {
// 	value, _ := new(big.Int).SetString(hex, 16)
// 	return value
// }

// func (c *MyCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
//     if x1.Sign() == 0 && y1.Sign() == 0 {
//         return x1, y1 // 无穷远点的双倍仍是自身
//     }

//     // 使用点倍增公式
//     λ := new(big.Int).Mul(x1, x1)
//     λ.Mul(λ, big.NewInt(3))
//     λ.Add(λ, c.B)
//     λ.Mod(λ, c.P)

//     denominator := new(big.Int).Mul(y1, big.NewInt(2))
//     denominator.Mod(denominator, c.P)
//     invDenominator := modInverse(denominator, c.P)
//     if invDenominator == nil {
//         return new(big.Int), new(big.Int) // 处理无效逆元
//     }
//     λ.Mul(λ, invDenominator)
//     λ.Mod(λ, c.P)

//     x3 := new(big.Int).Mul(λ, λ)
//     x3.Sub(x3, x1)
//     x3.Sub(x3, x1)
//     x3.Mod(x3, c.P)

//     y3 := new(big.Int).Sub(x1, x3)
//     y3.Mul(y3, λ)
//     y3.Sub(y3, y1)
//     y3.Mod(y3, c.P)

//     return x3, y3
// }

// // 3. 在自定义曲线类型上实现方法
// func (c *MyCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
//     // 处理无穷远点
//     if x1.Sign() == 0 && y1.Sign() == 0 {
//         return x2, y2
//     }
//     if x2.Sign() == 0 && y2.Sign() == 0 {
//         return x1, y1
//     }
// 	if x1.Cmp(x2) == 0 {
//         y2Neg := new(big.Int).Neg(y2)
//         y2Neg.Mod(y2Neg, c.P)
//         if y1.Cmp(y2Neg) == 0 {
//             return new(big.Int), new(big.Int) // 返回无穷远点
//         }
//     }

//     // 计算斜率 λ
//     λ := new(big.Int)
//     if x1.Cmp(x2) == 0 {
//         if y1.Cmp(y2) != 0 {
//             // 点互为负，结果为无穷远点
//             return new(big.Int), new(big.Int)
//         }
//         // 点倍增 (P == Q)
//         λ.Mul(x1, x1)
//         λ.Mul(λ, big.NewInt(3))
//         λ.Add(λ, c.B)
//         λ.Mod(λ, c.P)

//         denominator := new(big.Int).Mul(y1, big.NewInt(2))
//         denominator.Mod(denominator, c.P)
//         invDenominator := modInverse(denominator, c.P)
//         λ.Mul(λ, invDenominator)
//     } else {
//         // 点加法 (P != Q)
//         numerator := new(big.Int).Sub(y2, y1)
//         denominator := new(big.Int).Sub(x2, x1)
//         denominator.Mod(denominator, c.P)
//         invDenominator := modInverse(denominator, c.P)
//         λ.Mul(numerator, invDenominator)
//     }
//     λ.Mod(λ, c.P)

//     // 计算新坐标
//     x3 := new(big.Int).Mul(λ, λ)
//     x3.Sub(x3, x1)
//     x3.Sub(x3, x2)
//     x3.Mod(x3, c.P)

//     y3 := new(big.Int).Sub(x1, x3)
//     y3.Mul(y3, λ)
//     y3.Sub(y3, y1)
//     y3.Mod(y3, c.P)

//     return x3, y3
// }

// func (c *MyCurve) ScalarMult(x, y *big.Int, k []byte) (xOut, yOut *big.Int) {
//     var resultX, resultY *big.Int
//     for _, b := range k {
//         for i := 7; i >= 0; i-- { // 修正位处理顺序（高位到低位）
//             if resultX != nil {
//                 resultX, resultY = c.Double(resultX, resultY)
//             }
//             if (b >> uint(i) & 0x01) == 1 {
//                 if resultX == nil {
//                     resultX, resultY = x, y
//                 } else {
//                     resultX, resultY = c.Add(resultX, resultY, x, y)
//                 }
//             }
//         }
//     }
//     return resultX, resultY
// }

// // 4. 修改ChameleonHash相关代码
// type ChameleonHash struct {
// 	PrivateKey *ecdsa.PrivateKey
// 	PublicKey  *ecdsa.PublicKey
// }

// func NewChameleonHash() (*ChameleonHash, error) {
//     privateKey, err := ecdsa.GenerateKey(Secp256k1, rand.Reader)
//     if err != nil {
//         return nil, fmt.Errorf("密钥生成失败: %v", err)
//     }

//     pub := privateKey.PublicKey
//     valid := Secp256k1.IsOnCurve(pub.X, pub.Y)
//     fmt.Printf("=== 公钥验证 ===\n曲线名称: %s\nX: %x\nY: %x\n有效: %t\n",
//         Secp256k1.Params().Name,
//         pub.X,
//         pub.Y,
//         valid,
//     )

//     if !valid {
//         return nil, fmt.Errorf("公钥无效")
//     }

//     return &ChameleonHash{
//         PrivateKey: privateKey,
//         PublicKey:  &pub,
//     }, nil
// }

// func (ch *ChameleonHash) ComputeHash(message []byte, r *big.Int) *big.Int {
// 	hashInput := append(message, r.Bytes()...)
// 	hashed := sha256.Sum256(hashInput)
// 	h := new(big.Int).SetBytes(hashed[:])

// 	// 使用自定义曲线方法
// 	gHx, gHy := Secp256k1.ScalarBaseMult(h.Bytes())
// 	pkRx, pkRy := Secp256k1.ScalarMult(ch.PublicKey.X, ch.PublicKey.Y, r.Bytes())
// 	sumX, _ := Secp256k1.Add(gHx, gHy, pkRx, pkRy)

// 	return new(big.Int).Mod(sumX, Secp256k1.P)
// }

// // 模逆运算保持不变
// func modInverse(a, n *big.Int) *big.Int {
//     g := new(big.Int)
//     x := new(big.Int)
//     g.GCD(x, nil, a, n)
//     if g.Cmp(big.NewInt(1)) != 0 {
//         return nil // 明确返回nil表示不可逆
//     }
//     return x.Mod(x, n)
// }

// ============================================================================

func Sha3(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func Sha3Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

func Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	sig, err = secp256k1.Sign(hash, common.LeftPadBytes(prv.D.Bytes(), prv.Params().BitSize/8))
	return
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(S256(), pub)
	return &ecdsa.PublicKey{S256(), x, y}
}

func Decrypt(prv *ecdsa.PrivateKey, ct []byte) ([]byte, error) {
	key := ecies.ImportECDSA(prv)
	return key.Decrypt(rand.Reader, ct, nil, nil)
}

func S256() elliptic.Curve {
	return secp256k1.S256()
}

func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(S256(), s)
	return &ecdsa.PublicKey{S256(), x, y}, nil
}

func Ecrecover(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}

func Encrypt(pub *ecdsa.PublicKey, message []byte) ([]byte, error) {
	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(pub), message, nil, nil)
}

func FromECDSA(prv *ecdsa.PrivateKey) []byte {
	if prv == nil {
		return nil
	}
	return prv.D.Bytes()
}

func ToECDSA(prv []byte) *ecdsa.PrivateKey {
	if len(prv) == 0 {
		return nil
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	priv.D = common.BigD(prv)
	priv.PublicKey.X, priv.PublicKey.Y = S256().ScalarBaseMult(prv)
	return priv
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Sha3(pubBytes[1:])[12:])
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return ioutil.WriteFile(file, []byte(k), 0600)
}

// LoadECDSA loads a secp256k1 private key from the given file.
// The key data is expected to be hex-encoded.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}

	return ToECDSA(key), nil
}

// KeytoNodeID returns a marshaled representation of the given public key.
func KeytoNodeID(pub *ecdsa.PublicKey) common.NodeID {
	var id common.NodeID
	pbytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(pbytes)-1 != len(id) {
		panic(fmt.Errorf("need %d bit pubkey, got %d bits", (len(id)+1)*8, len(pbytes)))
	}
	copy(id[:], pbytes[1:])
	return id
}

// NodeIDtoKey returns the public key represented by the node ID.
// It returns an error if the ID is not a point on the curve.
func NodeIDtoKey(id common.NodeID) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(id) / 2
	p.X.SetBytes(id[:half])
	p.Y.SetBytes(id[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("not a point on the S256 curve")
	}
	return p, nil
}

// NodeIDtoAddress returns the address of a node
func NodeIDtoAddress(id common.NodeID) (common.Address, error) {
	p, err := NodeIDtoKey(id)
	if err != nil {
		return common.Address{}, err
	}
	return PubkeyToAddress(*p), nil
}

// To valid the signature with the given address
func SignatureValid(address common.Address, signature []byte, hash common.Hash) (bool, error) {
	pbk, err := SigToPub(hash[:], signature)
	if err != nil {
		return false, err
	}
	if PubkeyToAddress(*pbk) == address {
		return true, nil
	} else {
		return false, nil
	}
}

// use signature and hash to compute out the address
func Signature2Addr(signature []byte, hash common.Hash) (common.Address, error) {
	pbk, err := SigToPub(hash[:], signature)
	if err != nil {
		return common.Address{}, err
	}
	addr := PubkeyToAddress(*pbk)
	return addr, nil
}

func SignHash(hash common.Hash, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	sig, err = secp256k1.Sign(hash[:], common.LeftPadBytes(prv.D.Bytes(), prv.Params().BitSize/8))
	return
}

func GenerateSpecificKey(reader io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), reader)
}
