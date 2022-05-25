package main

import (
	"fmt"
	"strings"
	"strconv"
)

func mapAlphabetToNum() (alphabetMap map[string]int) {
	alphabetMap = map[string]int{
		"A": 0,
		"B": 1,
		"C": 2,
		"D": 3,
		"E": 4,
		"F": 5,
		"G": 6,
		"H": 7,
		"I": 8,
		"J": 9,
		"K": 10,
		"L": 11,
		"M": 12,
		"N": 13,
		"O": 14,
		"P": 15,
		"Q": 16,
		"R": 17,
		"S": 18,
		"T": 19,
		"U": 20,
		"V": 21,
		"W": 22,
		"X": 23,
		"Y": 24,
		"Z": 25,
	}

	return
}

func mapNumToAlphabet() (numberMap map[int]string) {
	numberMap = map[int]string{
		0: "A",
		1: "B",
		2: "C",
		3: "D",
		4: "E",
		5: "F",
		6: "G",
		7: "H",
		8: "I",
		9: "J",
		10: "K",
		11: "L",
		12: "M",
		13: "N",
		14: "O",
		15: "P",
		16: "Q",
		17: "R",
		18: "S",
		19: "T",
		20: "U",
		21: "V",
		22: "W",
		23: "X",
		24: "Y",
		25: "Z",
	}

	return
}

// This function converts the (possibly repeated) secret key to shift positions
func convertSecretKey(secretKey string) (keysToStringifiedNums []string) {
	for _, value := range secretKey {
		keysToStringifiedNums = append(keysToStringifiedNums, strconv.Itoa(mapAlphabetToNum()[string(value)]))
    }

	return keysToStringifiedNums
}

// This function encrypts plaintext and returns the cipher
func encrypt(plaintext, secretKey string) string {
	lengthOfPlaintext := len([]rune(plaintext))
	lengthOfSecretKey := len([]rune(secretKey))
	splitPlaintext := strings.Split(plaintext, "")
	cipher := []string{""}

	// It's assumed that the plaintext will always be longer than the secret key
	// or, at least, be of equal length
	if lengthOfPlaintext != lengthOfSecretKey {
		splitSecret := strings.Split(secretKey, "")

		// Unless the length of the plaintext is perfectly divisible by the length of the secret key,
		// there will be leftover characters. So, we repeat the secret (e.g "DUH") until the length
		// of the repeated secret (e.g "DUHDUH") is as long as or nearly as long as the length of the
		// plaintext (e.g "CRYPTO"). If (`lengthOfPlaintext` % `lengthOfSecretKey`) > 0, that means
		// there are unaccounted characters in the plaintext. These unaccounted characters are gotten
		// and stored in `secondPartOfRepeatedSecretKey`
		firstPartOfRepeatedSecretKey := strings.Repeat(secretKey, lengthOfPlaintext / lengthOfSecretKey)
		secondPartOfRepeatedSecretKey := strings.Join(splitSecret[:lengthOfPlaintext % lengthOfSecretKey], "")

		// The two parts of the repeated secret (if indeed there were leftover characters
		// as explained above) are combined and converted to shift positions using mapAlphabetToNum()
		keysToStringifiedNums := convertSecretKey(firstPartOfRepeatedSecretKey + secondPartOfRepeatedSecretKey)
		
		// The plaintext is converted to a cipher by shifting each character as specified by the secret
		for index, numOfShifts := range keysToStringifiedNums {
			numOfShifts, _ := strconv.Atoi(numOfShifts)
			positionOfPlaintextCharInAlphabet := mapAlphabetToNum()[splitPlaintext[index]]
			// The magic number 26 is used to keep the index given to mapNumToAlphabet()
			// between 0 and 25 (since each character in the alphabet maps to a number within that range)
			cipher = append(cipher, mapNumToAlphabet()[(positionOfPlaintextCharInAlphabet + numOfShifts) % 26])
		}
	} else if lengthOfPlaintext == lengthOfSecretKey {
		keysToStringifiedNums := convertSecretKey(secretKey)
		
		// The plaintext is converted to a cipher by shifting each character as specified by the secret
		for index, numOfShifts := range keysToStringifiedNums {
			numOfShifts, _ := strconv.Atoi(numOfShifts)
			positionOfPlaintextCharInAlphabet := mapAlphabetToNum()[splitPlaintext[index]]
			// The magic number 26 is used to keep the index given to mapNumToAlphabet()
			// between 0 and 25 (since each character in the alphabet maps to a number within that range)
			cipher = append(cipher, mapNumToAlphabet()[(positionOfPlaintextCharInAlphabet + numOfShifts) % 26])
		}
    }

	return strings.Join(cipher, "")
}

func decrypt(cipher, secretKey string) string {
	return ""
}

func main() {
	// fmt.Println(encrypt("HEAD", "DUH"))
	fmt.Println(encrypt("CRYPTO", "DUH"))
}