package main

import (
    "testing"
    "strings"
)

var testEncryptionPhrases = map[int]string{
    0: "HEAD", // should encrypt to "KYHG"
    1: "HEAD IS NOT BODY", // should encrypt to "KYHGCZQIAEIKB"
    2: "CRYPTO", // should encrypt to "FLFSNV"
    3: "Head", // should encrypt to "KYHG"
    4: "head", // should encrypt to "KYHG"
    5: "Head is not body", // should encrypt to "KYHGCZQIAEIKB"
    6: "Head Is Not Body", // should encrypt to "KYHGCZQIAEIKB"
}

var testDecryptionPhrases = map[int]string{
    0: "KYHG", // should decrypt to "HEAD"
    1: "KYHGCZQIAEIKB", // should decrypt to "HEADISNOTBODY"
    2: "FLFSNV", // should decrypt to "CRYPTO"
    3: "Kyhg", // should decrypt to "HEAD"
    4: "kyhg", // should decrypt to "HEAD"
    5: "KyhGczQIaeIkb", // should decrypt to "HEADISNOTBODY"
    6: "kyhgczqiaeikb", // should decrypt to "HEADISNOTBODY"
}

func TestEncrypt(t *testing.T) {
    secret := "DUH" // TODO: Test with different secrets

    for index, phrase := range testEncryptionPhrases {
        actualString := encrypt(phrase, secret)
        expectedString := strings.ToUpper(testDecryptionPhrases[index])

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
        expectedString := strings.ToUpper(strings.Join(strings.Split(testEncryptionPhrases[index], " "), ""))
        
        if actualString != expectedString{
            t.Errorf("Expected String(%s) is not same as"+
            " actual string (%s)", expectedString, actualString)
        }
    }
}