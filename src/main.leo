// The 'zPassport' program.
program zpassport_v001.aleo {
    // The ZPass record
    record ZPassport {
        owner: address,
        private private_credentials: PrivateCredentials,
        public public_credentials : PublicCredentials
    }

    // The private credentials struct
    struct PrivateCredentials {
        issuer: address,
        name : field,
        passport_number : u32,
        nationality: u8,
        dob: u32,
        expiry: u32
    }

    // The public credentials struct
    // This is the public information that is shared publicly onchain
    struct PublicCredentials {
        salt: scalar
    }

    // The full credentials struct 
    // Only used for hashed and verified against the signature
    struct FullCredentials {
        private_credentials: PrivateCredentials,
        public_credentials : PublicCredentials
    }

    // The mapping of issued commitments
    mapping issued: group => bool;

    // The mapping of invalidated commitments
    mapping invalidated: group => bool;

    // The count of issued ZPasses
    // Using key of 0field as global key
    mapping issuance_count: field => u128;

    async transition issue(
        private pri: PrivateCredentials,
        public pub: PublicCredentials,
    ) -> (ZPassport, Future) {
        // Construct the full credentials struct to be hashed and verified against the signature
        let credentials: FullCredentials = FullCredentials {
            private_credentials : pri,
            public_credentials : pub
        };


        //TODO: Add RSA/ECDSA signature verification once possible

        // Compute commitment to prevent double issuance
        let commit: group = BHP256::commit_to_group(pri, pub.salt);

        // Return the ZPass record and pass the commitment to store in the mapping
        return (
            ZPassport {
                owner: self.caller,
                private_credentials : pri,
                public_credentials : pub
            },
            issue_finalize(commit)
        );
    }

    async function issue_finalize(
        public commit: group
    ) {

        //TODO: Check issuing state certificates used are valid

        // Ensure the commitment is not already issued
        assert_eq(issued.get_or_use(commit, false), false);

        // Store the commitment in the mapping
        issued.set(commit, true);
        // Increment the issuance count
        issuance_count.set(0field, issuance_count.get_or_use(0field, 0u128) + 1u128);
    }

    async transition invalidate(
        zpassport: ZPassport
    ) -> Future {
        let credentials: FullCredentials = FullCredentials {
            private_credentials : zpassport.private_credentials,
            public_credentials : zpassport.public_credentials
        };
        let commit: group = BHP256::commit_to_group(zpassport.private_credentials, zpassport.public_credentials.salt);

        return invalidate_finalize(commit);
    }

    async function invalidate_finalize(
        public commit: group
    ) {
        // Store the commitment in the mapping
        invalidated.set(commit, true);
    }

    async transition is_invalid(
        credentials: FullCredentials
    ) -> Future {
        let commit: group = BHP256::commit_to_group(credentials.private_credentials, credentials.public_credentials.salt);

        return is_invalid_finalize(commit);
    }

    async function is_invalid_finalize(
        public commit: group
    ) {
        assert_eq(invalidated.get_or_use(commit, false), false);
    }
}

