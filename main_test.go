package main

import (
    "testing"
    "strings"
)

var testEncryptionPhrases = map[int]string{
    0: "HEAD", // should encrypt to "KYHG"
    1: "HEAD IS NOT BODY", // should encrypt to "KYHGCZQIAEIKB"
    2: "CRYPTO", // should encrypt to "FLFSNV"
}

var testDecryptionPhrases = map[int]string{
    0: "KYHG", // should decrypt to "HEAD"
    1: "KYHGCZQIAEIKB", // should decrypt to "HEAD IS NOT BODY"
    2: "FLFSNV", // should decrypt to "CRYPTO"
}

func TestEncrypt(t *testing.T) {
    secret := "DUH" // TODO: Test with different secrets

    for index, phrase := range testEncryptionPhrases {
        actualString := encrypt(phrase, secret)
        expectedString := testDecryptionPhrases[index]

        if actualString != expectedString{
            t.Errorf("Expected String(%s) is not same as"+
            " actual string (%s)", expectedString, actualString)
        }
    }
}

func TestDecrypt(t *testing.T) {
    secret := "DUH" // TODO: Test with different secrets

    for index, phrase := range testDecryptionPhrases {
        actualString := decrypt(phrase, secret)
        expectedString := strings.Join(strings.Split(testEncryptionPhrases[index], " "), "")
        
        if actualString != expectedString{
            t.Errorf("Expected String(%s) is not same as"+
            " actual string (%s)", expectedString, actualString)
        }
    }
}