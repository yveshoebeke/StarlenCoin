package utils

import "golang.org/x/crypto/bcrypt"

// functions:
//		HashAndSalt: Hash the password for storing.
//		ComparePasswords: Check if given password is correct.

// Hash the password.
func HashAndSalt(pwd []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Check if given password matches required one.
func ComparePasswords(hashedPwd string, plainPwd []byte) error { // Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	if err := bcrypt.CompareHashAndPassword(byteHash, plainPwd); err != nil {
		return err
	}
	return nil
}
