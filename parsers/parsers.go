package parsers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-circom-prover-verifier/types"
)

// PkString is the equivalent to the Pk struct in string representation, containing the ProvingKey
type PkString struct {
	A          [][]string          `json:"A"`
	B2         [][][]string        `json:"B2"`
	B1         [][]string          `json:"B1"`
	C          [][]string          `json:"C"`
	NVars      int                 `json:"nVars"`
	NPublic    int                 `json:"nPublic"`
	VkAlpha1   []string            `json:"vk_alpha_1"`
	VkDelta1   []string            `json:"vk_delta_1"`
	VkBeta1    []string            `json:"vk_beta_1"`
	VkBeta2    [][]string          `json:"vk_beta_2"`
	VkDelta2   [][]string          `json:"vk_delta_2"`
	HExps      [][]string          `json:"hExps"`
	DomainSize int                 `json:"domainSize"`
	PolsA      []map[string]string `json:"polsA"`
	PolsB      []map[string]string `json:"polsB"`
}

// WitnessString contains the Witness in string representation
type WitnessString []string

// ProofString is the equivalent to the Proof struct in string representation
type ProofString struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// VkString is the Verification Key data structure in string format (from json)
type VkString struct {
	Alpha []string   `json:"vk_alpha_1"`
	Beta  [][]string `json:"vk_beta_2"`
	Gamma [][]string `json:"vk_gamma_2"`
	Delta [][]string `json:"vk_delta_2"`
	IC    [][]string `json:"IC"`
}

// ParseWitness parses the json []byte data into the Witness struct
func ParseWitness(wJson []byte) (types.Witness, error) {
	var ws WitnessString
	err := json.Unmarshal(wJson, &ws)
	if err != nil {
		return nil, err
	}

	var w types.Witness
	for i := 0; i < len(ws); i++ {
		bi, err := stringToBigInt(ws[i])
		if err != nil {
			return nil, err
		}
		w = append(w, bi)
	}
	return w, nil
}

// ParsePk parses the json []byte data into the Pk struct
func ParsePk(pkJson []byte) (*types.Pk, error) {
	var pkStr PkString
	err := json.Unmarshal(pkJson, &pkStr)
	if err != nil {
		return nil, err
	}
	pk, err := pkStringToPk(pkStr)
	return pk, err
}

func pkStringToPk(ps PkString) (*types.Pk, error) {
	var p types.Pk
	var err error

	p.A, err = arrayStringToG1(ps.A)
	if err != nil {
		return nil, err
	}
	p.B2, err = arrayStringToG2(ps.B2)
	if err != nil {
		return nil, err
	}
	p.B1, err = arrayStringToG1(ps.B1)
	if err != nil {
		return nil, err
	}
	p.C, err = arrayStringToG1(ps.C)
	if err != nil {
		return nil, err
	}

	p.NVars = ps.NVars
	p.NPublic = ps.NPublic

	p.VkAlpha1, err = stringToG1(ps.VkAlpha1)
	if err != nil {
		return nil, err
	}

	p.VkDelta1, err = stringToG1(ps.VkDelta1)
	if err != nil {
		return nil, err
	}

	p.VkBeta1, err = stringToG1(ps.VkBeta1)
	if err != nil {
		return nil, err
	}
	p.VkBeta2, err = stringToG2(ps.VkBeta2)
	if err != nil {
		return nil, err
	}
	p.VkDelta2, err = stringToG2(ps.VkDelta2)
	if err != nil {
		return nil, err
	}

	p.HExps, err = arrayStringToG1(ps.HExps)
	if err != nil {
		return nil, err
	}

	p.DomainSize = ps.DomainSize

	p.PolsA, err = polsStringToBigInt(ps.PolsA)
	if err != nil {
		return nil, err
	}
	p.PolsB, err = polsStringToBigInt(ps.PolsB)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func proofStringToProof(pr ProofString) (*types.Proof, error) {
	var p types.Proof
	var err error
	p.A, err = stringToG1(pr.A)
	if err != nil {
		return nil, err
	}

	p.B, err = stringToG2(pr.B)
	if err != nil {
		return nil, err
	}

	p.C, err = stringToG1(pr.C)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// ParseProof takes a json []byte and outputs the *Proof struct
func ParseProof(pj []byte) (*types.Proof, error) {
	var pr ProofString
	err := json.Unmarshal(pj, &pr)
	if err != nil {
		return nil, err
	}
	p, err := proofStringToProof(pr)
	return p, err
}

// ParsePublicSignals takes a json []byte and outputs the []*big.Int struct
func ParsePublicSignals(pj []byte) ([]*big.Int, error) {
	var pr []string
	err := json.Unmarshal(pj, &pr)
	if err != nil {
		return nil, err
	}
	var public []*big.Int
	for _, s := range pr {
		sb, err := stringToBigInt(s)
		if err != nil {
			return nil, err
		}
		public = append(public, sb)
	}
	return public, nil
}

// ParseVk takes a json []byte and outputs the *Vk struct
func ParseVk(vj []byte) (*types.Vk, error) {
	var vr VkString
	err := json.Unmarshal(vj, &vr)
	if err != nil {
		return nil, err
	}
	v, err := vkStringToVk(vr)
	return v, err
}

func vkStringToVk(vr VkString) (*types.Vk, error) {
	var v types.Vk
	var err error
	v.Alpha, err = stringToG1(vr.Alpha)
	if err != nil {
		return nil, err
	}

	v.Beta, err = stringToG2(vr.Beta)
	if err != nil {
		return nil, err
	}

	v.Gamma, err = stringToG2(vr.Gamma)
	if err != nil {
		return nil, err
	}

	v.Delta, err = stringToG2(vr.Delta)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(vr.IC); i++ {
		p, err := stringToG1(vr.IC[i])
		if err != nil {
			return nil, err
		}
		v.IC = append(v.IC, p)
	}

	return &v, nil
}

// polsStringToBigInt is for taking string polynomials and converting it to *big.Int polynomials
func polsStringToBigInt(s []map[string]string) ([]map[int]*big.Int, error) {
	var o []map[int]*big.Int
	for i := 0; i < len(s); i++ {
		// var oi map[int]*big.Int
		oi := make(map[int]*big.Int)
		for j, v := range s[i] {
			si, err := stringToBigInt(v)
			if err != nil {
				return o, err
			}
			// oi = append(oi, si)
			jInt, err := strconv.Atoi(j)
			if err != nil {
				return o, err
			}
			oi[jInt] = si
		}
		o = append(o, oi)
	}
	return o, nil
}

// ArrayBigIntToString converts an []*big.Int into []string, used to output the Public Signals
func ArrayBigIntToString(bi []*big.Int) []string {
	var s []string
	for i := 0; i < len(bi); i++ {
		s = append(s, bi[i].String())
	}
	return s
}

func arrayStringToBigInt(s []string) ([]*big.Int, error) {
	var o []*big.Int
	for i := 0; i < len(s); i++ {
		si, err := stringToBigInt(s[i])
		if err != nil {
			return o, nil
		}
		o = append(o, si)
	}
	return o, nil
}

func stringToBigInt(s string) (*big.Int, error) {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("Can not parse string to *big.Int: %s", s)
	}
	return n, nil
}

func addPadding32(b []byte) []byte {
	if len(b) != 32 {
		b = addZPadding(b)
	}
	return b
}

func addZPadding(b []byte) []byte {
	var z [32]byte
	var r []byte
	r = append(r, z[len(b):]...) // add padding on the left
	r = append(r, b...)
	return r[:32]
}

func stringToBytes(s string) ([]byte, error) {
	if s == "1" {
		s = "0"
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("error parsing bigint stringToBytes")
	}
	b := bi.Bytes()
	if len(b) != 32 {
		b = addZPadding(b)
	}
	return b, nil

}

func arrayStringToG1(h [][]string) ([]*bn256.G1, error) {
	var o []*bn256.G1
	for i := 0; i < len(h); i++ {
		hi, err := stringToG1(h[i])
		if err != nil {
			return o, err
		}
		o = append(o, hi)
	}
	return o, nil
}

func arrayStringToG2(h [][][]string) ([]*bn256.G2, error) {
	var o []*bn256.G2
	for i := 0; i < len(h); i++ {
		hi, err := stringToG2(h[i])
		if err != nil {
			return o, err
		}
		o = append(o, hi)
	}
	return o, nil
}

func stringToG1(h []string) (*bn256.G1, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG1")
	}
	h = h[:2]
	hexa := false
	if len(h[0]) > 1 {
		if "0x" == h[0][:2] {
			hexa = true
		}
	}
	in := ""

	var b []byte
	var err error
	if hexa {
		for i := range h {
			in += strings.TrimPrefix(h[i], "0x")
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		// TODO use stringToBytes()
		if h[0] == "1" {
			h[0] = "0"
		}
		if h[1] == "1" {
			h[1] = "0"
		}
		bi0, ok := new(big.Int).SetString(h[0], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		bi1, ok := new(big.Int).SetString(h[1], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		b0 := bi0.Bytes()
		b1 := bi1.Bytes()
		if len(b0) != 32 {
			b0 = addZPadding(b0)
		}
		if len(b1) != 32 {
			b1 = addZPadding(b1)
		}

		b = append(b, b0...)
		b = append(b, b1...)
	}
	p := new(bn256.G1)
	_, err = p.Unmarshal(b)

	return p, err
}

func stringToG2(h [][]string) (*bn256.G2, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG2")
	}
	h = h[:2]
	hexa := false
	if len(h[0][0]) > 1 {
		if "0x" == h[0][0][:2] {
			hexa = true
		}
	}
	in := ""
	var b []byte
	var err error
	if hexa {
		for i := 0; i < len(h); i++ {
			for j := 0; j < len(h[i]); j++ {
				in += strings.TrimPrefix(h[i][j], "0x")
			}
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		bH, err := stringToBytes(h[0][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[0][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
	}

	p := new(bn256.G2)
	_, err = p.Unmarshal(b)
	return p, err
}

// ProofStringToSmartContractFormat converts the ProofString to a ProofString in the SmartContract format in a ProofString structure
func ProofStringToSmartContractFormat(s ProofString) ProofString {
	var rs ProofString
	rs.A = make([]string, 2)
	rs.B = make([][]string, 2)
	rs.B[0] = make([]string, 2)
	rs.B[1] = make([]string, 2)
	rs.C = make([]string, 2)

	rs.A[0] = s.A[0]
	rs.A[1] = s.A[1]
	rs.B[0][0] = s.B[0][1]
	rs.B[0][1] = s.B[0][0]
	rs.B[1][0] = s.B[1][1]
	rs.B[1][1] = s.B[1][0]
	rs.C[0] = s.C[0]
	rs.C[1] = s.C[1]
	rs.Protocol = s.Protocol
	return rs
}

// ProofToSmartContractFormat converts the *types.Proof to a ProofString in the SmartContract format in a ProofString structure
func ProofToSmartContractFormat(p *types.Proof) ProofString {
	s := ProofToString(p)
	return ProofStringToSmartContractFormat(s)
}

// ProofToString converts the Proof to ProofString
func ProofToString(p *types.Proof) ProofString {
	var ps ProofString
	ps.A = make([]string, 3)
	ps.B = make([][]string, 3)
	ps.B[0] = make([]string, 2)
	ps.B[1] = make([]string, 2)
	ps.B[2] = make([]string, 2)
	ps.C = make([]string, 3)

	a := p.A.Marshal()
	ps.A[0] = new(big.Int).SetBytes(a[:32]).String()
	ps.A[1] = new(big.Int).SetBytes(a[32:64]).String()
	ps.A[2] = "1"

	b := p.B.Marshal()
	ps.B[0][1] = new(big.Int).SetBytes(b[:32]).String()
	ps.B[0][0] = new(big.Int).SetBytes(b[32:64]).String()
	ps.B[1][1] = new(big.Int).SetBytes(b[64:96]).String()
	ps.B[1][0] = new(big.Int).SetBytes(b[96:128]).String()
	ps.B[2][0] = "1"
	ps.B[2][1] = "0"

	c := p.C.Marshal()
	ps.C[0] = new(big.Int).SetBytes(c[:32]).String()
	ps.C[1] = new(big.Int).SetBytes(c[32:64]).String()
	ps.C[2] = "1"

	ps.Protocol = "groth"

	return ps
}

// ProofToJson outputs the Proof i Json format
func ProofToJson(p *types.Proof) ([]byte, error) {
	ps := ProofToString(p)
	return json.Marshal(ps)
}

// ProofToHex converts the Proof to ProofString with hexadecimal strings
func ProofToHex(p *types.Proof) ProofString {
	var ps ProofString
	ps.A = make([]string, 3)
	ps.B = make([][]string, 3)
	ps.B[0] = make([]string, 2)
	ps.B[1] = make([]string, 2)
	ps.B[2] = make([]string, 2)
	ps.C = make([]string, 3)

	a := p.A.Marshal()
	ps.A[0] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(a[:32]).Bytes())
	ps.A[1] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(a[32:64]).Bytes())
	ps.A[2] = "1"

	b := p.B.Marshal()
	ps.B[0][1] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(b[:32]).Bytes())
	ps.B[0][0] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(b[32:64]).Bytes())
	ps.B[1][1] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(b[64:96]).Bytes())
	ps.B[1][0] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(b[96:128]).Bytes())
	ps.B[2][0] = "1"
	ps.B[2][1] = "0"

	c := p.C.Marshal()
	ps.C[0] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(c[:32]).Bytes())
	ps.C[1] = "0x" + hex.EncodeToString(new(big.Int).SetBytes(c[32:64]).Bytes())
	ps.C[2] = "1"

	ps.Protocol = "groth"

	return ps
}

// ProofToJsonHex outputs the Proof i Json format with hexadecimal strings
func ProofToJsonHex(p *types.Proof) ([]byte, error) {
	ps := ProofToHex(p)
	return json.Marshal(ps)
}

// ParseWitnessBin parses binary file representation of the Witness into the Witness struct
func ParseWitnessBin(f *os.File) (types.Witness, error) {
	var w types.Witness
	r := bufio.NewReader(f)
	for {
		b := make([]byte, 32)
		n, err := r.Read(b)
		if err == io.EOF {
			return w, nil
		} else if err != nil {
			return nil, err
		}
		if n != 32 {
			return nil, fmt.Errorf("error on value format, expected 32 bytes, got %v", n)
		}
		w = append(w, new(big.Int).SetBytes(swapEndianness(b[0:32])))
	}
}

// swapEndianness swaps the order of the bytes in the slice.
func swapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

func readNBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return b, err
	}
	return b, nil
}

// ParsePkBin parses binary file representation of the ProvingKey into the ProvingKey struct
func ParsePkBin(f *os.File) (*types.Pk, error) {
	o := 0
	var pk types.Pk
	r := bufio.NewReader(f)

	b, err := readNBytes(r, 12)
	if err != nil {
		return nil, err
	}
	pk.NVars = int(binary.LittleEndian.Uint32(b[:4]))
	pk.NPublic = int(binary.LittleEndian.Uint32(b[4:8]))
	pk.DomainSize = int(binary.LittleEndian.Uint32(b[8:12]))
	o += 12

	b, err = readNBytes(r, 8)
	if err != nil {
		return nil, err
	}
	pPolsA := int(binary.LittleEndian.Uint32(b[:4]))
	pPolsB := int(binary.LittleEndian.Uint32(b[4:8]))
	o += 8

	b, err = readNBytes(r, 20)
	if err != nil {
		return nil, err
	}
	pPointsA := int(binary.LittleEndian.Uint32(b[:4]))
	pPointsB1 := int(binary.LittleEndian.Uint32(b[4:8]))
	pPointsB2 := int(binary.LittleEndian.Uint32(b[8:12]))
	pPointsC := int(binary.LittleEndian.Uint32(b[12:16]))
	pPointsHExps := int(binary.LittleEndian.Uint32(b[16:20]))
	o += 20

	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkAlpha1 = new(bn256.G1)
	_, err = pk.VkAlpha1.Unmarshal(fromMont1Q(b))
	if err != nil {
		return nil, err
	}

	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkBeta1 = new(bn256.G1)
	_, err = pk.VkBeta1.Unmarshal(fromMont1Q(b))
	if err != nil {
		return nil, err
	}

	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkDelta1 = new(bn256.G1)
	_, err = pk.VkDelta1.Unmarshal(fromMont1Q(b))
	if err != nil {
		return nil, err
	}
	b, err = readNBytes(r, 128)
	if err != nil {
		return nil, err
	}
	pk.VkBeta2 = new(bn256.G2)
	_, err = pk.VkBeta2.Unmarshal(fromMont2Q(b))
	if err != nil {
		return nil, err
	}
	b, err = readNBytes(r, 128)
	if err != nil {
		return nil, err
	}
	pk.VkDelta2 = new(bn256.G2)
	_, err = pk.VkDelta2.Unmarshal(fromMont2Q(b))
	if err != nil {
		return nil, err
	}
	o += 448
	if o != pPolsA {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPolsA, o)
	}

	// PolsA
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 4)
		if err != nil {
			return nil, err
		}
		keysLength := int(binary.LittleEndian.Uint32(b[:4]))
		o += 4
		polsMap := make(map[int]*big.Int)
		for j := 0; j < keysLength; j++ {
			bK, err := readNBytes(r, 4)
			if err != nil {
				return nil, err
			}
			key := int(binary.LittleEndian.Uint32(bK[:4]))
			o += 4

			b, err := readNBytes(r, 32)
			if err != nil {
				return nil, err
			}
			polsMap[key] = new(big.Int).SetBytes(fromMont1R(b[:32]))
			o += 32
		}
		pk.PolsA = append(pk.PolsA, polsMap)
	}
	if o != pPolsB {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPolsB, o)
	}
	// PolsB
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 4)
		if err != nil {
			return nil, err
		}
		keysLength := int(binary.LittleEndian.Uint32(b[:4]))
		o += 4
		polsMap := make(map[int]*big.Int)
		for j := 0; j < keysLength; j++ {
			bK, err := readNBytes(r, 4)
			if err != nil {
				return nil, err
			}
			key := int(binary.LittleEndian.Uint32(bK[:4]))
			o += 4

			b, err := readNBytes(r, 32)
			if err != nil {
				return nil, err
			}
			polsMap[key] = new(big.Int).SetBytes(fromMont1R(b[:32]))
			o += 32
		}
		pk.PolsB = append(pk.PolsB, polsMap)
	}
	if o != pPointsA {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsA, o)
	}
	// A
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(fromMont1Q(b))
		if err != nil {
			return nil, err
		}
		pk.A = append(pk.A, p1)
		o += 64
	}
	if o != pPointsB1 {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsB1, o)
	}
	// B1
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(fromMont1Q(b))
		if err != nil {
			return nil, err
		}
		pk.B1 = append(pk.B1, p1)
		o += 64
	}
	if o != pPointsB2 {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsB2, o)
	}
	// B2
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 128)
		if err != nil {
			return nil, err
		}
		p2 := new(bn256.G2)
		_, err = p2.Unmarshal(fromMont2Q(b))
		if err != nil {
			return nil, err
		}
		pk.B2 = append(pk.B2, p2)
		o += 128
	}
	if o != pPointsC {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsC, o)
	}
	// C
	zb := make([]byte, 64)
	z := new(bn256.G1)
	_, err = z.Unmarshal(zb)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pk.NPublic+1; i++ {
		pk.C = append(pk.C, z)
	}
	for i := pk.NPublic + 1; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(fromMont1Q(b))
		if err != nil {
			return nil, err
		}
		pk.C = append(pk.C, p1)
		o += 64
	}
	if o != pPointsHExps {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsHExps, o)
	}
	// HExps
	for i := 0; i < pk.DomainSize; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(fromMont1Q(b))
		if err != nil {
			return nil, err
		}
		pk.HExps = append(pk.HExps, p1)
	}
	return &pk, nil
}

func fromMont1Q(m []byte) []byte {
	a := new(big.Int).SetBytes(swapEndianness(m[:32]))
	b := new(big.Int).SetBytes(swapEndianness(m[32:64]))

	x := coordFromMont(a, types.Q)
	y := coordFromMont(b, types.Q)
	if bytes.Equal(x.Bytes(), big.NewInt(1).Bytes()) {
		x = big.NewInt(0)
	}
	if bytes.Equal(y.Bytes(), big.NewInt(1).Bytes()) {
		y = big.NewInt(0)
	}

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	if len(xBytes) != 32 {
		xBytes = addZPadding(xBytes)
	}
	if len(yBytes) != 32 {
		yBytes = addZPadding(yBytes)
	}

	var p []byte
	p = append(p, xBytes...)
	p = append(p, yBytes...)

	return p
}

func fromMont2Q(m []byte) []byte {
	a := new(big.Int).SetBytes(swapEndianness(m[:32]))
	b := new(big.Int).SetBytes(swapEndianness(m[32:64]))
	c := new(big.Int).SetBytes(swapEndianness(m[64:96]))
	d := new(big.Int).SetBytes(swapEndianness(m[96:128]))

	x := coordFromMont(a, types.Q)
	y := coordFromMont(b, types.Q)
	z := coordFromMont(c, types.Q)
	t := coordFromMont(d, types.Q)

	if bytes.Equal(x.Bytes(), big.NewInt(1).Bytes()) {
		x = big.NewInt(0)
	}
	if bytes.Equal(y.Bytes(), big.NewInt(1).Bytes()) {
		y = big.NewInt(0)
	}
	if bytes.Equal(z.Bytes(), big.NewInt(1).Bytes()) {
		z = big.NewInt(0)
	}
	if bytes.Equal(t.Bytes(), big.NewInt(1).Bytes()) {
		t = big.NewInt(0)
	}

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	zBytes := z.Bytes()
	tBytes := t.Bytes()
	if len(xBytes) != 32 {
		xBytes = addZPadding(xBytes)
	}
	if len(yBytes) != 32 {
		yBytes = addZPadding(yBytes)
	}
	if len(zBytes) != 32 {
		zBytes = addZPadding(zBytes)
	}
	if len(tBytes) != 32 {
		tBytes = addZPadding(tBytes)
	}

	var p []byte
	p = append(p, yBytes...) // swap
	p = append(p, xBytes...)
	p = append(p, tBytes...)
	p = append(p, zBytes...)

	return p
}

func fromMont1R(m []byte) []byte {
	a := new(big.Int).SetBytes(swapEndianness(m[:32]))

	x := coordFromMont(a, types.R)

	return x.Bytes()
}

func fromMont2R(m []byte) []byte {
	a := new(big.Int).SetBytes(swapEndianness(m[:32]))
	b := new(big.Int).SetBytes(swapEndianness(m[32:64]))
	c := new(big.Int).SetBytes(swapEndianness(m[64:96]))
	d := new(big.Int).SetBytes(swapEndianness(m[96:128]))

	x := coordFromMont(a, types.R)
	y := coordFromMont(b, types.R)
	z := coordFromMont(c, types.R)
	t := coordFromMont(d, types.R)

	var p []byte
	p = append(p, y.Bytes()...) // swap
	p = append(p, x.Bytes()...)
	p = append(p, t.Bytes()...)
	p = append(p, z.Bytes()...)

	return p
}

func coordFromMont(u, q *big.Int) *big.Int {
	return new(big.Int).Mod(
		new(big.Int).Mul(
			u,
			new(big.Int).ModInverse(
				new(big.Int).Lsh(big.NewInt(1), 256),
				q,
			),
		),
		q,
	)
}

func sortedKeys(m map[int]*big.Int) []int {
	keys := make([]int, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// PkToGoBin converts the ProvingKey (*types.Pk) into binary format defined by
// go-circom-prover-verifier.  PkGoBin is a own go-circom-prover-verifier
// binary format that allows to go faster when parsing.
func PkToGoBin(pk *types.Pk) ([]byte, error) {
	var r []byte
	o := 0
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(pk.NVars))
	r = append(r, b[:]...)

	binary.LittleEndian.PutUint32(b[:], uint32(pk.NPublic))
	r = append(r, b[:]...)

	binary.LittleEndian.PutUint32(b[:], uint32(pk.DomainSize))
	r = append(r, b[:]...)
	o += 12

	// reserve space for pols (A, B) pos
	b = [4]byte{}
	r = append(r, b[:]...) // 12:16
	r = append(r, b[:]...) // 16:20
	o += 8
	// reserve space for points (A, B1, B2, C, HExps) pos
	r = append(r, b[:]...) // 20:24
	r = append(r, b[:]...) // 24
	r = append(r, b[:]...) // 28
	r = append(r, b[:]...) // 32
	r = append(r, b[:]...) // 36:40
	o += 20

	pb1 := pk.VkAlpha1.Marshal()
	r = append(r, pb1[:]...)
	pb1 = pk.VkBeta1.Marshal()
	r = append(r, pb1[:]...)
	pb1 = pk.VkDelta1.Marshal()
	r = append(r, pb1[:]...)
	pb2 := pk.VkBeta2.Marshal()
	r = append(r, pb2[:]...)
	pb2 = pk.VkDelta2.Marshal()
	r = append(r, pb2[:]...)
	o += 448

	// polsA
	binary.LittleEndian.PutUint32(r[12:16], uint32(o))
	for i := 0; i < pk.NVars; i++ {
		binary.LittleEndian.PutUint32(b[:], uint32(len(pk.PolsA[i])))
		r = append(r, b[:]...)
		o += 4
		for _, j := range sortedKeys(pk.PolsA[i]) {
			v := pk.PolsA[i][j]
			binary.LittleEndian.PutUint32(b[:], uint32(j))
			r = append(r, b[:]...)
			r = append(r, addPadding32(v.Bytes())...)
			o += 32 + 4
		}
	}
	// polsB
	binary.LittleEndian.PutUint32(r[16:20], uint32(o))
	for i := 0; i < pk.NVars; i++ {
		binary.LittleEndian.PutUint32(b[:], uint32(len(pk.PolsB[i])))
		r = append(r, b[:]...)
		o += 4
		for _, j := range sortedKeys(pk.PolsB[i]) {
			v := pk.PolsB[i][j]
			binary.LittleEndian.PutUint32(b[:], uint32(j))
			r = append(r, b[:]...)
			r = append(r, addPadding32(v.Bytes())...)
			o += 32 + 4
		}
	}
	// A
	binary.LittleEndian.PutUint32(r[20:24], uint32(o))
	for i := 0; i < pk.NVars; i++ {
		pb1 = pk.A[i].Marshal()
		r = append(r, pb1[:]...)
		o += 64
	}
	// B1
	binary.LittleEndian.PutUint32(r[24:28], uint32(o))
	for i := 0; i < pk.NVars; i++ {
		pb1 = pk.B1[i].Marshal()
		r = append(r, pb1[:]...)
		o += 64
	}
	// B2
	binary.LittleEndian.PutUint32(r[28:32], uint32(o))
	for i := 0; i < pk.NVars; i++ {
		pb2 = pk.B2[i].Marshal()
		r = append(r, pb2[:]...)
		o += 128
	}
	// C
	binary.LittleEndian.PutUint32(r[32:36], uint32(o))
	for i := pk.NPublic + 1; i < pk.NVars; i++ {
		pb1 = pk.C[i].Marshal()
		r = append(r, pb1[:]...)
		o += 64
	}
	// HExps
	binary.LittleEndian.PutUint32(r[36:40], uint32(o))
	for i := 0; i < pk.DomainSize+1; i++ {
		pb1 = pk.HExps[i].Marshal()
		r = append(r, pb1[:]...)
		o += 64
	}

	return r[:], nil
}

// ParsePkGoBin parses go-circom-prover-verifier binary file representation of
// the ProvingKey into ProvingKey struct (*types.Pk).  PkGoBin is a own
// go-circom-prover-verifier binary format that allows to go faster when
// parsing.
func ParsePkGoBin(f *os.File) (*types.Pk, error) {
	o := 0
	var pk types.Pk
	r := bufio.NewReader(f)

	b, err := readNBytes(r, 12)
	if err != nil {
		return nil, err
	}
	pk.NVars = int(binary.LittleEndian.Uint32(b[:4]))
	pk.NPublic = int(binary.LittleEndian.Uint32(b[4:8]))
	pk.DomainSize = int(binary.LittleEndian.Uint32(b[8:12]))
	o += 12

	b, err = readNBytes(r, 8)
	if err != nil {
		return nil, err
	}
	pPolsA := int(binary.LittleEndian.Uint32(b[:4]))
	pPolsB := int(binary.LittleEndian.Uint32(b[4:8]))
	o += 8

	b, err = readNBytes(r, 20)
	if err != nil {
		return nil, err
	}
	pPointsA := int(binary.LittleEndian.Uint32(b[:4]))
	pPointsB1 := int(binary.LittleEndian.Uint32(b[4:8]))
	pPointsB2 := int(binary.LittleEndian.Uint32(b[8:12]))
	pPointsC := int(binary.LittleEndian.Uint32(b[12:16]))
	pPointsHExps := int(binary.LittleEndian.Uint32(b[16:20]))
	o += 20

	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkAlpha1 = new(bn256.G1)
	_, err = pk.VkAlpha1.Unmarshal(b)
	if err != nil {
		return &pk, err
	}
	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkBeta1 = new(bn256.G1)
	_, err = pk.VkBeta1.Unmarshal(b)
	if err != nil {
		return &pk, err
	}
	b, err = readNBytes(r, 64)
	if err != nil {
		return nil, err
	}
	pk.VkDelta1 = new(bn256.G1)
	_, err = pk.VkDelta1.Unmarshal(b)
	if err != nil {
		return &pk, err
	}
	b, err = readNBytes(r, 128)
	if err != nil {
		return nil, err
	}
	pk.VkBeta2 = new(bn256.G2)
	_, err = pk.VkBeta2.Unmarshal(b)
	if err != nil {
		return &pk, err
	}
	b, err = readNBytes(r, 128)
	if err != nil {
		return nil, err
	}
	pk.VkDelta2 = new(bn256.G2)
	_, err = pk.VkDelta2.Unmarshal(b)
	if err != nil {
		return &pk, err
	}
	o += 448
	if o != pPolsA {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPolsA, o)
	}

	// PolsA
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 4)
		if err != nil {
			return nil, err
		}
		keysLength := int(binary.LittleEndian.Uint32(b[:4]))
		o += 4
		polsMap := make(map[int]*big.Int)
		for j := 0; j < keysLength; j++ {
			bK, err := readNBytes(r, 4)
			if err != nil {
				return nil, err
			}
			key := int(binary.LittleEndian.Uint32(bK[:4]))
			o += 4

			b, err := readNBytes(r, 32)
			if err != nil {
				return nil, err
			}
			polsMap[key] = new(big.Int).SetBytes(b[:32])
			o += 32
		}
		pk.PolsA = append(pk.PolsA, polsMap)
	}
	if o != pPolsB {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPolsB, o)
	}
	// PolsB
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 4)
		if err != nil {
			return nil, err
		}
		keysLength := int(binary.LittleEndian.Uint32(b[:4]))
		o += 4
		polsMap := make(map[int]*big.Int)
		for j := 0; j < keysLength; j++ {
			bK, err := readNBytes(r, 4)
			if err != nil {
				return nil, err
			}
			key := int(binary.LittleEndian.Uint32(bK[:4]))
			o += 4

			b, err := readNBytes(r, 32)
			if err != nil {
				return nil, err
			}
			polsMap[key] = new(big.Int).SetBytes(b[:32])
			o += 32
		}
		pk.PolsB = append(pk.PolsB, polsMap)
	}
	if o != pPointsA {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsA, o)
	}
	// A
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		pk.A = append(pk.A, p1)
		o += 64
	}
	if o != pPointsB1 {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsB1, o)
	}
	// B1
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		pk.B1 = append(pk.B1, p1)
		o += 64
	}
	if o != pPointsB2 {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsB2, o)
	}
	// B2
	for i := 0; i < pk.NVars; i++ {
		b, err = readNBytes(r, 128)
		if err != nil {
			return nil, err
		}
		p2 := new(bn256.G2)
		_, err = p2.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		pk.B2 = append(pk.B2, p2)
		o += 128
	}
	if o != pPointsC {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsC, o)
	}
	// C
	zb := make([]byte, 64)
	z := new(bn256.G1)
	_, err = z.Unmarshal(zb)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pk.NPublic+1; i++ {
		pk.C = append(pk.C, z)
	}
	for i := pk.NPublic + 1; i < pk.NVars; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		pk.C = append(pk.C, p1)
		o += 64
	}
	if o != pPointsHExps {
		return nil, fmt.Errorf("Unexpected offset, expected: %v, actual: %v", pPointsHExps, o)
	}
	// HExps
	for i := 0; i < pk.DomainSize+1; i++ {
		b, err = readNBytes(r, 64)
		if err != nil {
			return nil, err
		}
		p1 := new(bn256.G1)
		_, err = p1.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		pk.HExps = append(pk.HExps, p1)
	}

	return &pk, nil
}
