package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
	"reflect"
)

// References:
// The code below is inspired by section 4.1.6 of SEC 1 Ver 2.0, page 47-48 (53 and 54 in the pdf):
// 	https://www.secg.org/sec1-v2.pdf
// As well as Pieter Wuille's work in Bitcoin, here is the original thread:
// 	https://bitcointalk.org/index.php?topic=6430.msg93940#msg93940
// And here's another post from this thread about benchmarking:
// 	https://bitcointalk.org/index.php?topic=6430.msg100334#msg100334
// And here's his code in bitcoin-core gh on public key recovery:
// 	https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h
// Here is another thread about this, which explains how recovery works:
// 	https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work
// We're also in luck because btcsuite/btcec has fully implemented public key recovery from ecdsa:
// 	https://github.com/btcsuite/btcd/blob/b3e6b/btcec/signature.go#L417

func main(){
	// In this code, we will use the privateKey to sign a sample test message.
	// We will then attempt to verify the signature using the realPublicKey,
	// which is the public key associated with the privateKey. Then, we
	// use another, "unrelated" public key - recoveredPublicKey - to see that
	// it also passes the signature verification. This will show that there
	// is are always multiple public key passing signature verification.
	// This observation is helpful, because it gives context to the later described
	// public key recovery. It will also prove that the proposed signature scheme
	// for derived keys on the BitClout blockchain is secure. Let's see this in action:
	privateKeyBase58Check := "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	realPublicKeyBase58Check := "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	recoveredPublicKeyBase58Check := "tBCKYQieeL52ocrVptetL8xvYBBSSL6infjaU7kxDEogogNo2etx2c"
	message := fmt.Sprintf("This is a test%v",10)

	// Decode private key into bytes
	privateKeyBytes, _, err := Base58CheckDecode(privateKeyBase58Check)
	if err != nil {
		panic(fmt.Errorf("error in decoding private key %v", err))
	}

	// Turn private key bytes into *btcec.PrivateKey
	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)

	// Confirm realPublicKeyBase58Check is the real public key
	publicKeyBase58Check := Base58CheckEncode(publicKey.SerializeCompressed(), false)
	if !reflect.DeepEqual(realPublicKeyBase58Check, publicKeyBase58Check) {
		panic("Error: public keys are not matching")
	}

	// Sign message
	messageBytes := []byte(message)
	messageHash := Sha256DoubleHash(messageBytes)
	signature, err := privateKey.Sign(messageHash[:])
	if err != nil {
		panic("Error: failed signing message")
	}

	// Verify signed message using the real public key
	if !reflect.DeepEqual(true, signature.Verify(messageHash[:], publicKey)) {
		panic("Error: failed verifying signature with real public key")
	}

	// We will now use the recovered public key to verify the signature.
	// First, let us decode the base58Check into *btcec.PublicKey.
	recoveredPublicKeyBytes, _, err := Base58CheckDecode(recoveredPublicKeyBase58Check)
	if err != nil {
		panic("Error: failed decoding recovered public key")
	}
	recoveredPublicKey, err := btcec.ParsePubKey(recoveredPublicKeyBytes, btcec.S256())
	if err != nil {
		panic("Error: failed parsing recovered public key")
	}

	// Verify signed message using the recovered public key
	if !reflect.DeepEqual(true, signature.Verify(messageHash[:], recoveredPublicKey)) {
		panic("Error: failed verifying signature with recovered public key")
	}

	// As we can see, recovered public key passed signature verification.
	// This happened because for any signature, there are at most 4 public keys that could
	// produce a given signature (although it is very unlikely there will be more than 2).
	// This stems from a property of ECDSA signatures. I will now explain how we
	// use this fact in public key recovery in BitClout derived key signatures.

	fmt.Println("Yup, there are more than one valid public key per signature.")

	// The recovered public key has been extracted from the {r, s} pair of the signature.
	// To do this we've done some math using a special parameter, called iteration, which
	// is a 2-bit number between 0-3. The real public key represents a different iteration
	// value applied to {r, s} than the recovered public key.
	// The standard way to encode a {r, s} ecdsa signature is a DER format which is:
	// 0x30 <length of whole message> <0x02> <length of R> <R> 0x2 <length of S> <S>.
	// The 0x30 control byte, or 48 in base-10, is static and doesn't affect the signature.
	// When using DER format, we're not encoding the information about iteration. To make
	// up for this, we would transmit the signer public key together with the signature.
	// However, there is another signature format, known as Compact Format, which includes
	// the iteration information in the signature encoding:
	// < byte of 27 + iteration >< padded bytes for signature R><padded bytes for signature S>
	// The computation of the correct iteration is pushed on the signer, and the verifier recovers
	// the public key based on the sig first byte information. It is important to compare this recovered
	// public key with an existing key certificate, or in our case, the derived key entry.
	// In BitClout txns, we've stored all signatures in DER format, so switching to
	// the Compact format isn't feasible. On the other hand, we could merge these two encodings
	// into our custom encoding that supports both owner and derived key signed transactions.
	// The proposed format is:
	// <0x30 + [(1 + iteration) if derived]> <length of whole message> <0x02> <length of R> <R> 0x2 <length of S> <S>.
	// This way signature tells us if message was signed with a an owner or with a derived key, and if so which key was used.
	// So we don't need to transmit any information about the derived key used to sign a message.
	// The MsgBitCloutTxn signed by a derived public key will look identical to the one signed with owner public key.

	// Below we will show how we can use this new signature encoding to
	// verify signatures in BitClout. First we sign the message and encode
	// the iteration in the first byte of the DER signature. To accomplish
	// this, we sign the message and combine the DER and Compact encodings.
	signatureDerived, err := SignTransactionWithDerivedKey(messageBytes, privateKey)
	if err != nil {
		panic("Error: failed signing by a derived key")
	}

	// We now retrieve the iteration from signatureDerived.
	// We subtract 1, because iteration is currently 1-4 and it must be between 0-3.
	sigByte := signatureDerived[0]
	iteration := sigByte - DERControlByte - 1

	// We convert the signature back into DER signature.
	signatureDerived[0] = DERControlByte
	sig, err := btcec.ParseDERSignature(signatureDerived, btcec.S256())
	if err != nil {
		panic("Error: failed verifying the derived key signature")
	}

	// We now recover the signer public key from the signature. First we turn
	// signature it into Compact format using SignatureSerializeCompactWithIteration.
	sigCompact := SignatureSerializeCompactWithIteration(sig, int(iteration), false)

	// Now we use the btcec library to get the correct signer public key.
	signerPublicKey, _, err := btcec.RecoverCompact(btcec.S256(), sigCompact, messageHash[:])
	if err != nil {
		panic("Error: failed recovering public key from signature")
	}

	// Let's compare the recovered signer public key with the real public key,
	// associated with the signer private key.
	if !reflect.DeepEqual(realPublicKeyBase58Check, Base58CheckEncode(signerPublicKey.SerializeCompressed(), false)) {
		panic("Error: failed comparing real public key with the signature recovered public key")
	}

	// Now, someone security-minded will instantly consider if it's possible to spoof a signature using
	// one of the other valid public keys. Answer is no, because such a public key would require a previous
	// AuthorizeDerivedKey txn existing in the CloutChain. This means consensus would need to accept
	// an owner-signed or accessSignature, or derivedKeyEntry (certificate) for this spoofed public key in
	// _connectAuthorizeDerivedKey().

	fmt.Println("As we can see, we correctly recovered signer public key from the signature.")
}

const (
	// Note that 0x30 is 48 in base 10
	DERControlByte = 48
	// Compact signature encoding control byte
	CompactControlByte = 27
)

// SignTransactionWithDerivedKey the signature contains solution iteration,
// which allows us to recover signer public key from the signature.
func SignTransactionWithDerivedKey(txnBytes []byte, privateKey *btcec.PrivateKey) ([]byte, error){
	// Compute a hash of the transaction bytes without the signature
	// portion and sign it with the passed private key.
	txnSignatureHash := Sha256DoubleHash(txnBytes)
	txnSignature, err := privateKey.Sign(txnSignatureHash[:])
	if err != nil {
		return nil, err
	}

	// If we're signing with a derived key, we will encode recovery byte into
	// the signature.
	txnSignatureBytes := txnSignature.Serialize()
	txnSignatureCompact, err := btcec.SignCompact(btcec.S256(), privateKey, txnSignatureHash[:], false)
	if err != nil {
		return nil, err
	}

	// Get the public key solution based on btcsuite/btcd RecoverCompact method.
	// Iteration is between 1-4.
	iteration := 1 + int((txnSignatureCompact[0] - CompactControlByte) & ^byte(4))

	// Encode the public key solution in the first byte of the signature.
	// Normally DER signatures start with 0x30 or 48 in base-10. We set
	// the first byte to 0x30 + 0x1-4 depending on the solution.
	txnSignatureBytes[0] = byte(DERControlByte + iteration)

	return txnSignatureBytes, nil
}

// SignatureSerializeCompactWithIteration turns a btcec.Signature on S256 into a compact encoding. The isCompressed
// parameter should be used if the given signature should reference a compressed public key or not.
// If successful, the bytes of the compact signature will be returned in the format:
// <(byte of 27+public key solution)+4 if compressed >< padded bytes for signature R><padded bytes for signature S>
// where the R and S parameters are padded up to the bitlengh. Based on btcsuite/btcd implementation
// https://github.com/btcsuite/btcd/blob/f5a1fb9/btcec/signature.go#L383
func SignatureSerializeCompactWithIteration(sig *btcec.Signature, iter int, isCompressedKey bool) []byte {
	result := make([]byte, 1, 2 * (btcec.S256().BitSize / 8) + 1)
	result[0] = CompactControlByte + byte(iter)
	if isCompressedKey {
		result[0] += 4
	}

	curvelen := (btcec.S256().BitSize + 7) / 8

	// Pad R and S to curvelen if needed.
	bytelen := (sig.R.BitLen() + 7) / 8
	if bytelen < curvelen {
		result = append(result,
			make([]byte, curvelen-bytelen)...)
	}
	result = append(result, sig.R.Bytes()...)

	bytelen = (sig.S.BitLen() + 7) / 8
	if bytelen < curvelen {
		result = append(result,
			make([]byte, curvelen-bytelen)...)
	}
	result = append(result, sig.S.Bytes()...)

	return result
}

// --- Helper functions ---
func Base58CheckEncode(input []byte, isPrivate bool) string {
	Base58PrefixPublicKey := [3]byte{0x11, 0xc2, 0x0}
	prefix := Base58PrefixPublicKey
	if isPrivate {
		prefix = Base58PrefixPublicKey
	}
	return Base58CheckEncodeWithPrefix(input, prefix)
}

func Base58CheckEncodeWithPrefix(input []byte, prefix [3]byte) string {
	b := []byte{}
	b = append(b, prefix[:]...)
	b = append(b, input[:]...)
	cksum := _checksum(b)
	b = append(b, cksum[:]...)
	return base58.Encode(b)
}

func Base58CheckDecode(input string) (_result []byte, _prefix []byte, _err error) {
	return Base58CheckDecodePrefix(input, 3 /*prefixLen*/)
}

func Base58CheckDecodePrefix(input string, prefixLen int) (_result []byte, _prefix []byte, _err error) {
	decoded := base58.Decode(input)
	if len(decoded) < 5 {
		return nil, nil, errors.Wrap(fmt.Errorf("CheckDecode: Invalid input format"), "")
	}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if _checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, nil, errors.Wrap(fmt.Errorf("CheckDecode: Checksum does not match"), "")
	}
	prefix := decoded[:prefixLen]
	payload := decoded[prefixLen : len(decoded)-4]
	return payload, prefix, nil
}

func _checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}


type BlockHash [32]byte

func Sha256DoubleHash(input []byte) *BlockHash {
	hashBytes := merkletree.Sha256DoubleHash(input)
	ret := &BlockHash{}
	copy(ret[:], hashBytes[:])
	return ret
}

