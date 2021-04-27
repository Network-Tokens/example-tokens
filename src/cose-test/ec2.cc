#define USE_CBOR_CONTEXT
#include <cstring>
#include <cose/cose.h>
#include <cn-cbor/cn-cbor.h>
#include <iostream>
#include <vector>

using namespace std;


// CBOR array consisting of [x, y] components of EC2 key
static const uint8_t COSE_KEY[] = {
    0x82, 0x58, 0x20, 0xa7, 0x1c, 0x98, 0x19, 0xf5,
    0x7f, 0x1a, 0xf3, 0xfd, 0xdd, 0x3e, 0xe7, 0x14,
    0x3c, 0xdb, 0x96, 0x05, 0xc1, 0x0f, 0x94, 0x1e,
    0x09, 0x68, 0x3f, 0x3a, 0xb2, 0xfc, 0x17, 0x3a,
    0x7f, 0xef, 0x66, 0x58, 0x20, 0x9e, 0x0a, 0x5a,
    0x42, 0x33, 0xc5, 0x97, 0xda, 0x56, 0x30, 0x90,
    0xa8, 0x2f, 0x49, 0xce, 0x23, 0x53, 0x3f, 0x5d,
    0x44, 0x90, 0x2a, 0x56, 0x11, 0xc1, 0x49, 0x1c,
    0x9b, 0xf8, 0xfe, 0xa1, 0x7e,
};


static const uint8_t COSE_TOKEN[] = {
    0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58,
    0x28, 0xa4, 0x63, 0x62, 0x69, 0x70, 0x1a, 0x0a,
    0x64, 0x00, 0xc9, 0x63, 0x65, 0x78, 0x70, 0x1a,
    0x60, 0x88, 0x4c, 0xed, 0x63, 0x65, 0x6e, 0x76,
    0x63, 0x64, 0x65, 0x76, 0x64, 0x74, 0x69, 0x65,
    0x72, 0x67, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e,
    0x64, 0x58, 0x40, 0x5c, 0x7a, 0x97, 0x74, 0x46,
    0x3b, 0xec, 0x3a, 0x39, 0x0c, 0x62, 0xbe, 0xbd,
    0x9a, 0x29, 0x16, 0x4c, 0xf8, 0x2f, 0x6e, 0x2f,
    0x39, 0x5e, 0x80, 0x62, 0x65, 0x32, 0x0a, 0xf3,
    0x9f, 0xfc, 0x2e, 0xba, 0x1d, 0x4b, 0x79, 0x01,
    0x5b, 0x2f, 0x07, 0xd6, 0x6f, 0xe9, 0xe8, 0x1a,
    0xeb, 0x56, 0xc6, 0x3c, 0x78, 0x06, 0xc0, 0xe1,
    0x49, 0x22, 0x66, 0xb4, 0x4c, 0xd6, 0x77, 0x42,
    0xce, 0x85, 0xf1,
};


struct AllocatorContext : cn_cbor_context {
    AllocatorContext() : cn_cbor_context { allocate, release, this } {}

private:
    static const size_t CHUNK_SIZE;

    size_t remaining = 0;
    vector<string> blocks;

    static void * allocate( size_t count, size_t size, void * ptr )
    {
        AllocatorContext * ctx = (AllocatorContext*) ptr;

        const size_t required = count * size;
        if( required > ctx->remaining ) {
            ctx->remaining = max( CHUNK_SIZE, required );
            ctx->blocks.push_back( std::string( ctx->remaining, '\0' ) );
        }

        const size_t pos = ctx->blocks.back().size() - ctx->remaining;
        ctx->remaining -= required;
        return ctx->blocks.back().data() + pos;
    }

    static void release( void * ptr, void * ) {}
};

inline const size_t AllocatorContext::CHUNK_SIZE = 2048;


// TODO: These are defined in the C file, but after reading the spec, I think I
// trust the values in the Python library more...
//

#define KEY_KTY    1
#define KEY_ALG    3
#define KEY_CRV  (-1)
#define KEY_X    (-2)
#define KEY_Y    (-3)
#define KEY_D    (-4)


int
main()
{
    // Create an allocator to use for memory management.
    AllocatorContext ctx;
    cose_errback err;
    cn_cbor_errback cberr;

    cn_cbor * pubkey_array = cn_cbor_decode( COSE_KEY, sizeof(COSE_KEY),
        &ctx, &cberr );
    if( !pubkey_array ) {
      cerr << "Failed to parse public key: " << (int) err.err << endl;
      return 1;
    }

    auto x = cn_cbor_index( pubkey_array, 0 );
    auto y = cn_cbor_index( pubkey_array, 1 );

    auto key_cbor = cn_cbor_map_create( &ctx, NULL );

    // Set KTY
    auto p = cn_cbor_int_create( COSE_Key_Type_EC2, &ctx, &cberr );
    if( !p ) {
        cerr << "Failed to allocate: " << (int) err.err << endl;
        return 1;
    }
    if( !cn_cbor_mapput_int( key_cbor, KEY_KTY, p, &ctx, &cberr ) ) {
        cerr << "Failed to set key: " << (int) err.err << endl;
        return 1;
    }

    // Set ALG
    p = cn_cbor_int_create( COSE_Algorithm_ECDSA_SHA_256, &ctx, &cberr );
    if( !p ) {
        cerr << "Failed to allocate: " << (int) err.err << endl;
        return 1;
    }
    if( !cn_cbor_mapput_int( key_cbor, KEY_ALG, p, &ctx, &cberr ) ) {
        cerr << "Failed to set key: " << (int) err.err << endl;
        return 1;
    }

    // Set CRV
    p = cn_cbor_int_create( COSE_Curve_P256, &ctx, &cberr );
    if( !p ) {
        cerr << "Failed to allocate: " << (int) err.err << endl;
        return 1;
    }
    if( !cn_cbor_mapput_int( key_cbor, KEY_CRV, p, &ctx, &cberr ) ) {
        cerr << "Failed to set key: " << (int) err.err << endl;
        return 1;
    }

    // Set X
    if( !cn_cbor_mapput_int( key_cbor, KEY_X, x, &ctx, &cberr ) ) {
        cerr << "Failed to set key: " << (int) err.err << endl;
        return 1;
    }

    // Set Y
    if( !cn_cbor_mapput_int( key_cbor, KEY_Y, y, &ctx, &cberr ) ) {
        cerr << "Failed to set key: " << (int) err.err << endl;
        return 1;
    }

    // Load the key
    auto key = (HCOSE_KEY) COSE_KEY_FromCbor( key_cbor, &ctx, &err );
    if( !key ) {
        cerr << "Failed to load key: " << (int) err.err << endl;
        return 1;
    }

    // Decode the encoded CBOR object into a COSE Encrypt0 message
    int type = 0;
    auto token = (HCOSE_SIGN1) COSE_Decode( COSE_TOKEN, sizeof(COSE_TOKEN),
            &type, COSE_sign1_object, &ctx, &err );
    if( !token ) {
        cerr << "Failed to load token: " << (int) err.err << endl;
        return 1;
    }

    // Validate the Sign1 message using the public key
    if( !COSE_Sign1_validate2( token, key, &err )) {
        cerr << "Failed to decrypt token: " << (int) err.err << endl;
        return 1;
    }

    auto payload = COSE_get_cbor( (HCOSE) token );
    if( !payload ) {
        cerr << "Failed to extract payload: " << (int) err.err << endl;
        return 1;
    }
    auto metadata = cn_cbor_index( payload, 2 );
    if( !metadata ) {
        cerr << "Failed to extract metadata: " << (int) err.err << endl;
        return 1;
    }

    // Decode the signed payload
    cn_cbor_errback cn_err;
    cn_cbor * cbor = cn_cbor_decode( metadata->v.bytes, metadata->length, &ctx, &cn_err );
    if( !cbor ) {
        cerr << "Failed to decode signed payload: " << (int) cn_err.err << endl;
        return 1;
    }

    // Get the handles to the fields
    auto bip = cn_cbor_mapget_string( cbor, "bip" );
    auto exp = cn_cbor_mapget_string( cbor, "exp" );

    // Quick validation...
    if( 
        bip->type != CN_CBOR_UINT
     || exp->type != CN_CBOR_UINT
    ) {
        return 1;
    }

    // Output payload content
    cout << "bip: " << bip->v.uint << endl;
    cout << "exp: " << exp->v.uint << endl;
    return 0;
}
