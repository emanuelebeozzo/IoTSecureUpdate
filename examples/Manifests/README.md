# Examples description
    
- Example 1: Single Proofs inside the manifest encoded in Base64 (proof name: 'qsort.cpc') with original size of 338.4kB, compressed 31.9kB. Total size: 43kB. Parsing & signature: 0.06s, 1536kB. Proofs verification: 10.91s, 171,97MB

- Example 2: Double Proof inside the manifest encoded in Base64:
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2MB, compressed 31.3KB.
        Total size: 84kB.
        Parsing & signature: 0.07s, 1536kB.
        Proofs verification: 10.91 + 7.37 = 18,28 s, 171,97MB
        
- Example 3: Triple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        Total size: 122kB.
        Parsing & signature: 0.08s, 1664kB.
        Proofs verification: 10.91 + 7.37 + 12.61 = 30,89s, 213,5MB

- Example 4: Triple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        Total size: 86kB.
        Parsing & signature: 0.07s, 1536kB.
        Proofs verification: 10.91 + 7.37 + 0.30 = 18.58s, 171,97MB

- Example 5: Quadruple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        4. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        Total size: 124kB
        Parsing & signature: 0.08s, 1664kB. 
        Proofs verification: 10.91 + 7.37 + 0.30 + 12.61 = 31,19s, 213,5MB

- Example 6: Quadruple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        4. Proof name: 'bitcnts.cpc" with original size of 10.9MB, compressed 1.2Kb.
        Total size: 88kB.
        Parsing & signature: 0.07s, 1536kB. 
        Proofs verification: 10.91 + 7.37 + 0.30 + 0.29 = 18,87s, 171,97MB

- Example 7: Quintuple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        4. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        5. Proof name: 'hw_cfp.cpc" with original size of 305,2kB, compressed 46,9Kb.
        Total size: 185kB.
        Parsing & signature: 0.10s, 1664kB. 
        Proofs verification: 10.91 + 7.37 + 0.30 + 12.61 + 1.12 = 32,31s, 213,5MB

- Example 8: Quintuple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        4. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        5. Proof name: 'bitcnts.cpc" with original size of 10.9MB, compressed 1.2Kb.
        Total size: 126kB.
        Parsing & signature: 0.08s, 1664kB. 
        Proofs verification: 10.91 + 7.37 + 0.30 + 0.29 + 12.61 = 31,48s, 213,5MB

- Example 9: Sextuple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        4. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        5. Proof name: 'hw_cfp.cpc" with original size of 305.2kB, compressed 46.9Kb.
        6. Proof name: 'pic32mz2.cpc" with original size of 40.8kB, compressed 6.6Kb.
        Total size: 194kB.
        Parsing & signature: 0.10s, 1664kB.
        Proofs verification: 10.91 + 7.37 + 0.30 + 12.61 + 1.12 + 0.43 = 32,74s, 213,5MB

- Example 10: Sextuple Proof inside the manifest encoded in Base64
        1. Proof name: 'qsort.cpc', with original size of 338.4kB, compressed 31.9kB.
        2. Proof name: 'sha.cpc', with original size of 318.2kB, compressed 31.3KB.
        3. Proof name: 'dijk.cpc' with original size of 310.2kB, compressed 28.80kB.
        4. Proof name: 'bmath.cpc' with original size of 11.4kB, compressed 1.3kB.
        5. Proof name: 'bitcnts.cpc" with original size of 10.9MB, compressed 1.2Kb.
        6. Proof name: 'pic32mz2.cpc" with original size of 40.8kB, compressed 6.6Kb.
        Total size: 135kB.
        Parsing & signature: 0.10s, 1664kB.
        Proofs verification: 10.91 + 7.37 + 0.30 + 0.29 + 12.61 + 0.43 = 31,91s, 213,5MB

