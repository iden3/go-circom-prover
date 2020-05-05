package prover

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	cryptoConstants "github.com/iden3/go-iden3-crypto/constants"
	"math/big"
)

type TableG1 struct {
	data []*bn256.G1
}

func (t TableG1) GetData() []*bn256.G1 {
	return t.data
}

// Compute table of gsize elements as ::
//  Table[0] = Inf
//  Table[1] = a[0]
//  Table[2] = a[1]
//  Table[3] = a[0]+a[1]
//  .....
//  Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
func (t *TableG1) NewTableG1(a []*bn256.G1, gsize int, toaffine bool) {
	// EC table
	table := make([]*bn256.G1, 0)

	// We need at least gsize elements. If not enough, fill with 0
	a_ext := make([]*bn256.G1, 0)
	a_ext = append(a_ext, a...)

	for i := len(a); i < gsize; i++ {
		a_ext = append(a_ext, new(bn256.G1).ScalarBaseMult(big.NewInt(0)))
	}

	elG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	table = append(table, elG1)
	last_pow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG1 := new(bn256.G1)
		// if power of 2
		if i&(i-1) == 0 {
			last_pow2 = i
			elG1.Set(a_ext[nelems])
			nelems++
		} else {
			elG1.Add(table[last_pow2], table[i-last_pow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG1)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info)
		}
	}
	t.data = table
}

func (t TableG1) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G1 elements
func (t *TableG1) MulTableG1(k []*big.Int, Q_prev *bn256.G1, gsize int) *bn256.G1 {
	// We need at least gsize elements. If not enough, fill with 0
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)

	for i := len(k); i < gsize; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}

	Q := new(bn256.G1).ScalarBaseMult(big.NewInt(0))

	msb := getMsb(k_ext)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(bn256.G1).Add(Q, Q)
		b := getBit(k_ext, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if Q_prev != nil {
		return Q.Add(Q, Q_prev)
	} else {
		return Q
	}
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func MulTableNoDoubleG1(t []TableG1, k []*big.Int, Q_prev *bn256.G1, gsize int) *bn256.G1 {
	// We need at least gsize elements. If not enough, fill with 0
	min_nelems := len(t) * gsize
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)
	for i := len(k); i < min_nelems; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G1, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(k_ext[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(k_ext[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(bn256.G1).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G1).Add(R, R)
		R.Add(R, Q[i-1])
	}

	if Q_prev != nil {
		return R.Add(R, Q_prev)
	} else {
		return R
	}
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func ScalarMultG1(a []*bn256.G1, k []*big.Int, Q_prev *bn256.G1, gsize int) *bn256.G1 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := TableG1{}
	Q := new(bn256.G1).ScalarBaseMult(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.NewTableG1(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.MulTableG1(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.NewTableG1(a[(ntables-1)*gsize:], gsize, false)
	Q = table.MulTableG1(k[(ntables-1)*gsize:], Q, gsize)

	if Q_prev != nil {
		return Q.Add(Q, Q_prev)
	} else {
		return Q
	}
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func ScalarMultNoDoubleG1(a []*bn256.G1, k []*big.Int, Q_prev *bn256.G1, gsize int) *bn256.G1 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := TableG1{}

	// We need at least gsize elements. If not enough, fill with 0
	min_nelems := ntables * gsize
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)
	for i := len(k); i < min_nelems; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G1, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < ntables-1; j++ {
		table.NewTableG1(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(k_ext[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(k_ext[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], table.data[b])
			}
		}
	}
	table.NewTableG1(a[(ntables-1)*gsize:], gsize, false)
	msb := getMsb(k_ext[(ntables-1)*gsize:])

	for i := msb - 1; i >= 0; i-- {
		b := getBit(k_ext[(ntables-1)*gsize:], i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q[i].Add(Q[i], table.data[b])
		}
	}

	// Consolidate Addition
	R := new(bn256.G1).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G1).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if Q_prev != nil {
		return R.Add(R, Q_prev)
	} else {
		return R
	}
}

/////

// TODO - How can avoid replicating code in G2?
//G2

type TableG2 struct {
	data []*bn256.G2
}

func (t TableG2) GetData() []*bn256.G2 {
	return t.data
}

// Compute table of gsize elements as ::
//  Table[0] = Inf
//  Table[1] = a[0]
//  Table[2] = a[1]
//  Table[3] = a[0]+a[1]
//  .....
//  Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
// TODO -> toaffine = True doesnt work. Problem with Marshal/Unmarshal
func (t *TableG2) NewTableG2(a []*bn256.G2, gsize int, toaffine bool) {
	// EC table
	table := make([]*bn256.G2, 0)

	// We need at least gsize elements. If not enough, fill with 0
	a_ext := make([]*bn256.G2, 0)
	a_ext = append(a_ext, a...)

	for i := len(a); i < gsize; i++ {
		a_ext = append(a_ext, new(bn256.G2).ScalarBaseMult(big.NewInt(0)))
	}

	elG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	table = append(table, elG2)
	last_pow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG2 := new(bn256.G2)
		// if power of 2
		if i&(i-1) == 0 {
			last_pow2 = i
			elG2.Set(a_ext[nelems])
			nelems++
		} else {
			elG2.Add(table[last_pow2], table[i-last_pow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG2)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info)
		}
	}
	t.data = table
}

func (t TableG2) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G2 elements
func (t *TableG2) MulTableG2(k []*big.Int, Q_prev *bn256.G2, gsize int) *bn256.G2 {
	// We need at least gsize elements. If not enough, fill with 0
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)

	for i := len(k); i < gsize; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}

	Q := new(bn256.G2).ScalarBaseMult(big.NewInt(0))

	msb := getMsb(k_ext)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(bn256.G2).Add(Q, Q)
		b := getBit(k_ext, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if Q_prev != nil {
		return Q.Add(Q, Q_prev)
	} else {
		return Q
	}
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func MulTableNoDoubleG2(t []TableG2, k []*big.Int, Q_prev *bn256.G2, gsize int) *bn256.G2 {
	// We need at least gsize elements. If not enough, fill with 0
	min_nelems := len(t) * gsize
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)
	for i := len(k); i < min_nelems; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G2, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(k_ext[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(k_ext[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(bn256.G2).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G2).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if Q_prev != nil {
		return R.Add(R, Q_prev)
	} else {
		return R
	}
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func ScalarMultG2(a []*bn256.G2, k []*big.Int, Q_prev *bn256.G2, gsize int) *bn256.G2 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := TableG2{}
	Q := new(bn256.G2).ScalarBaseMult(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.NewTableG2(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.MulTableG2(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.NewTableG2(a[(ntables-1)*gsize:], gsize, false)
	Q = table.MulTableG2(k[(ntables-1)*gsize:], Q, gsize)

	if Q_prev != nil {
		return Q.Add(Q, Q_prev)
	} else {
		return Q
	}
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func ScalarMultNoDoubleG2(a []*bn256.G2, k []*big.Int, Q_prev *bn256.G2, gsize int) *bn256.G2 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := TableG2{}

	// We need at least gsize elements. If not enough, fill with 0
	min_nelems := ntables * gsize
	k_ext := make([]*big.Int, 0)
	k_ext = append(k_ext, k...)
	for i := len(k); i < min_nelems; i++ {
		k_ext = append(k_ext, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G2, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < ntables-1; j++ {
		table.NewTableG2(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(k_ext[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(k_ext[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], table.data[b])
			}
		}
	}
	table.NewTableG2(a[(ntables-1)*gsize:], gsize, false)
	msb := getMsb(k_ext[(ntables-1)*gsize:])

	for i := msb - 1; i >= 0; i-- {
		b := getBit(k_ext[(ntables-1)*gsize:], i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q[i].Add(Q[i], table.data[b])
		}
	}

	// Consolidate Addition
	R := new(bn256.G2).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G2).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if Q_prev != nil {
		return R.Add(R, Q_prev)
	} else {
		return R
	}
}

// Return most significant bit position in a group of Big Integers
func getMsb(k []*big.Int) int {
	msb := 0

	for _, el := range k {
		tmp_msb := el.BitLen()
		if tmp_msb > msb {
			msb = tmp_msb
		}
	}
	return msb
}

// Return ith bit in group of Big Integers
func getBit(k []*big.Int, i int) uint {
	table_idx := uint(0)

	for idx, el := range k {
		b := el.Bit(i)
		table_idx += (b << idx)
	}
	return table_idx
}
