package gocircomprover

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmallCircuitGenerateProf(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("testdata/small/proving_key.json")
	require.Nil(t, err)
	pk, err := ParsePk(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("testdata/small/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	assert.Equal(t, Witness{big.NewInt(1), big.NewInt(33), big.NewInt(3), big.NewInt(11)}, w)

	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)

	proofStr, err := ProofToJson(proof)
	assert.Nil(t, err)

	err = ioutil.WriteFile("testdata/small/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("testdata/small/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// verify the proof
	vkJson, err := ioutil.ReadFile("testdata/small/verification_key.json")
	require.Nil(t, err)
	vk, err := ParseVk(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, pubSignals)
	assert.True(t, v)

	// to verify the proof with snarkjs:
	// snarkjs verify --vk testdata/small/verification_key.json -p testdata/small/proof.json --pub testdata/small/public.json
}

func TestBigCircuitGenerateProf(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("testdata/big/proving_key.json")
	require.Nil(t, err)
	pk, err := ParsePk(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("testdata/big/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)

	proofStr, err := ProofToJson(proof)
	assert.Nil(t, err)

	err = ioutil.WriteFile("testdata/big/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("testdata/big/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// verify the proof
	vkJson, err := ioutil.ReadFile("testdata/big/verification_key.json")
	require.Nil(t, err)
	vk, err := ParseVk(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, pubSignals)
	assert.True(t, v)

	// to verify the proof with snarkjs:
	// snarkjs verify --vk testdata/big/verification_key.json -p testdata/big/proof.json --pub testdata/big/public.json
}

func BenchmarkGenerateProof(b *testing.B) {
	provingKeyJson, err := ioutil.ReadFile("testdata/big/proving_key.json")
	require.Nil(b, err)
	pk, err := ParsePk(provingKeyJson)
	require.Nil(b, err)

	witnessJson, err := ioutil.ReadFile("testdata/big/witness.json")
	require.Nil(b, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		GenerateProof(pk, w)
	}
}
