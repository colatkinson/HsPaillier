module Crypto.Paillier where

import Data.Maybe
import Crypto.Random
import Crypto.Number.Prime
import Crypto.Number.Generate (generateBetween)
import Crypto.Number.ModArithmetic

type PlainText = Integer

type CipherText = Integer

data PubKey = PubKey{  bits :: Int  -- ^ e.g., 2048
                     , nModulo :: Integer -- ^ n = pq
                     , generator :: Integer -- ^ generator = n+1
                     , nSquare :: Integer -- ^ n^2
                    } deriving (Show)

data PrvKey = PrvKey{  lambda :: Integer -- ^ lambda(n) = lcm(p-1, q-1)
                     , x :: Integer
                    } deriving (Show)

-- TODO: Deal with the fact that generated primes aren't necessarily the correct bit size

genKey :: Int -> IO(PubKey, PrvKey)
genKey nBits = loop
    where
        loop = do
            -- Generate random primes
            (p, q) <- generatePQ

            let modulo = p * q

            -- Public key parameters
            let g = modulo + 1
            let square = modulo * modulo
            -- Private key parameters
            let phi_n = lcm (p - 1) (q - 1)
            let maybeU = inverse ((expSafe g phi_n square - 1) `div` modulo) modulo
            if isNothing maybeU then
                error "genKey failed."
            else
                return (PubKey{bits=nBits, nModulo=modulo, generator=g, nSquare=square},
                        PrvKey{lambda=phi_n, x=fromJust maybeU})
        generatePQ = do
            -- Generate the first prime
            p <- generatePrime (nBits `div` 2)

            q <- generateQ p
            return (p, q)
        generateQ p = do
            -- Generate the second prime
            q <- generatePrime (nBits `div` 2)
            -- Repeat until they're different
            if p == q then generateQ p else return q


-- | deterministic version of encryption
_encrypt :: PubKey -> PlainText -> Integer -> CipherText
_encrypt pubKey plaintext r =
    result
    where result = (g_m*r_n) `mod` n_2
          n_2 = nSquare pubKey
          g_m = expSafe (generator pubKey) plaintext n_2
          r_n = expSafe r (nModulo pubKey) n_2

generateR :: PubKey -> Integer -> IO Integer
generateR pubKey guess = do
    if guess >= nModulo pubKey || (gcd (nModulo pubKey) guess > 1) then do
        nextGuess <- generateBetween 1 (nModulo pubKey -1)
        generateR pubKey nextGuess
    else
        return guess

encrypt :: PubKey -> PlainText -> IO CipherText
encrypt pubKey plaintext = do
    r <- generateR pubKey (nModulo pubKey)
    return $ _encrypt pubKey plaintext r

decrypt :: PrvKey -> PubKey -> CipherText -> PlainText
decrypt prvKey pubKey ciphertext =
    let c_lambda = expSafe ciphertext (lambda prvKey) (nSquare pubKey)
        l_c_lamdba = (c_lambda - 1) `div` nModulo pubKey
    in  l_c_lamdba * x prvKey `mod` nModulo pubKey

-- | ciphetext muliplication is known as homomorphic addition of plaintexts
cipherMul :: PubKey -> CipherText -> CipherText -> CipherText
cipherMul pubKey c1 c2 = c1*c2 `mod` nSquare pubKey

-- | Homomorphic multiplication of plaintexts
-- An encrypted plaintext raised to the power of another plaintext will decrypt to the product of the two plaintexts.
cipherExp :: PubKey -> CipherText -> PlainText -> CipherText
cipherExp pubKey c1 p1 = expSafe c1 p1 (nSquare pubKey)
