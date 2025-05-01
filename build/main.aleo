program zpassport_v1.aleo;

struct PrivateCredentials:
    issuer as address;
    subject as address;
    dob as u32;
    nationality as field;
    expiry as u32;

struct PublicCredentials:
    salt as scalar;

record ZPassport:
    owner as address.private;
    private_credentials as PrivateCredentials.private;
    public_credentials as PublicCredentials.public;

struct FullCredentials:
    private_credentials as PrivateCredentials;
    public_credentials as PublicCredentials;

mapping issued:
    key as group.public;
    value as boolean.public;

mapping invalidated:
    key as group.public;
    value as boolean.public;

mapping issuance_count:
    key as field.public;
    value as u128.public;

function issue:
    input r0 as signature.private;
    input r1 as PrivateCredentials.private;
    input r2 as PublicCredentials.public;
    cast r1 r2 into r3 as FullCredentials;
    hash.psd2 r3 into r4 as field;
    sign.verify r0 r1.issuer r4 into r5;
    assert.eq r5 true;
    commit.bhp256 self.caller r2.salt into r6 as group;
    cast self.caller r1 r2 into r7 as ZPassport.record;
    async issue r6 into r8;
    output r7 as ZPassport.record;
    output r8 as zpassport_v1.aleo/issue.future;

finalize issue:
    input r0 as group.public;
    get.or_use issued[r0] false into r1;
    assert.eq r1 false;
    set true into issued[r0];
    get.or_use issuance_count[0field] 0u128 into r2;
    add r2 1u128 into r3;
    set r3 into issuance_count[0field];

function invalidate:
    input r0 as ZPassport.record;
    cast r0.private_credentials r0.public_credentials into r1 as FullCredentials;
    commit.bhp256 r1 r0.public_credentials.salt into r2 as group;
    async invalidate r2 into r3;
    output r3 as zpassport_v1.aleo/invalidate.future;

finalize invalidate:
    input r0 as group.public;
    set true into invalidated[r0];

function is_invalid:
    input r0 as FullCredentials.private;
    commit.bhp256 r0 r0.public_credentials.salt into r1 as group;
    async is_invalid r1 into r2;
    output r2 as zpassport_v1.aleo/is_invalid.future;

finalize is_invalid:
    input r0 as group.public;
    get.or_use invalidated[r0] false into r1;
    assert.eq r1 false;
