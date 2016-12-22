{-# LANGUAGE DeriveDataTypeable #-}

module Main where
import qualified Crypto.Paillier as P

main = do
    (pubKey, prvKey) <- P.genKey 10
    print (pubKey, prvKey)
    let p = 2 :: Integer
    c <- P.encrypt pubKey p
    putStrLn $ "ciphertext 1: " ++ show c
    putStrLn $ "plaintext 1: " ++ show (P.decrypt prvKey pubKey c)
    let p' = 3 :: Integer
    c' <- P.encrypt pubKey p'
    putStrLn $ "ciphertext 2: " ++ show c'
    putStrLn $ "plaintext 2: " ++ show (P.decrypt prvKey pubKey c')
    let c'' = P.cipherMul pubKey c c'
    putStrLn $ "ciphertext (1*2): " ++ show c''
    putStrLn $ "plaintext (1+2): " ++ show (P.decrypt prvKey pubKey c'')
