/* Test suite for ARIA v1.0
 * Nikolay Dubina (dubyna.mykola@gmail.com)
 */
#include <array>
#include <deque>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <string>

#include "aria.h"

using namespace std;
using namespace aria;

bool eqseg(const segment& l, const segment& r){
    bool equal = l.size() == r.size();
    for(int i = 0; i < l.size() && equal; ++i)
        equal = l[i] == r[i];
    return equal;
}


/* assertion tests */
void test_circular_rotation(){
    segment a =            to_segment<16>("0xff00ff00ff00ff00ff00ff00ff00ff00");
    assert(eqseg(a >>  4,  to_segment<16>("0x0ff00ff00ff00ff00ff00ff00ff00ff0")));
    assert(eqseg(a >>  8,  to_segment<16>("0x00ff00ff00ff00ff00ff00ff00ff00ff")));
    assert(eqseg(a >> 16,  to_segment<16>("0xff00ff00ff00ff00ff00ff00ff00ff00")));
    assert(eqseg(a <<  4,  to_segment<16>("0xf00ff00ff00ff00ff00ff00ff00ff00f")));
    assert(eqseg(a <<  8,  to_segment<16>("0x00ff00ff00ff00ff00ff00ff00ff00ff")));
    assert(eqseg(a << 16,  to_segment<16>("0xff00ff00ff00ff00ff00ff00ff00ff00")));

    segment w1 =            to_segment<16>("0x2afbea741e1746dd55c63ba1afcea0a5");
    assert(eqseg(w1 >> 19,  to_segment<16>("0xd414a55f7d4e83c2e8dbaab8c77435f9")));
    assert(eqseg(w1 << 19,  to_segment<16>("0x53a0f0ba36eaae31dd0d7e75052957df")));
}

/* source article tests */
template<int KEYSIZE, int ROUNDS>
bool test_consistency(const std::array<uint8_t, KEYSIZE>& master_key, 
        const array<segment, 4>& ws, const array<segment, ROUNDS>& encryption_keys,
        const array<segment, ROUNDS>& decryption_keys,
        const segment& ciphertext_target)
{
    bool eq = true;
    bool success = true;

    /* CHECKING VALUES OF W */
    auto ws_test = initialize<KEYSIZE>(master_key);

    cout << "VALUES OF W" << endl;
    for(int i = 0; i < ws.size(); ++i){
        eq = eqseg(ws[i], ws_test[i]);
        success &= eq;
    
        string w = "W" + to_string(i);
        cout << w << " : " << (eq ? "SUCCESS" : "FAIL") << endl
             << "   " << w << " target=" << '\t' << to_string(ws[i]) << endl
             << "   " << w << " test=" << '\t' << to_string(ws_test[i]) << endl;
    }
    cout << "VALUES OF W: " << (success ? "SUCCESS" : "FAIL") << endl << endl;

    /* CHECKING VALUES OF KEYS */
    cout << "VALUES OF ROUND KEYS"<< endl;
    array<segment, ROUNDS> keys_test_e = generate_keys<ROUNDS>(false, ws_test);
    array<segment, ROUNDS> keys_test_d = generate_keys<ROUNDS>(true, ws_test);
    for(int i = 0; i < ROUNDS; ++i){
        bool eq = true;

        eq = eqseg(keys_test_e[i], encryption_keys[i]);
        success &= eq;

        cout << "   ENCRYPTION ROUND " << to_string(i + 1) << " : " << (eq ? "SUCCESS" : "FAIL") << endl
             << "       key target decryption =" << '\t' << to_string(encryption_keys[i]) << endl
             << "       key test   decryption =" << '\t' << to_string(keys_test_e[i]) << endl;

        eq = eqseg(keys_test_d[i], decryption_keys[i]);
        success &= eq;

        cout << "   DECRYPTION ROUND " << to_string(i + 1) << " : " << (eq ? "SUCCESS" : "FAIL") << endl
             << "       key target decryption =" << '\t' << to_string(decryption_keys[i]) << endl
             << "       key test   decryption =" << '\t' << to_string(keys_test_d[i]) << endl;
    }
    cout << "VALUES OF ROUND KEYS: " << (success ? "SUCCESS" : "FAIL") << endl << endl;

    segment plaintext = to_segment<16>("0x00112233445566778899aabbccddeeff");
    
    /* ENCRYPTION CHECK */
    segment ciphertext_test = encrypt<KEYSIZE>(plaintext, master_key);

    eq = eqseg(ciphertext_test, ciphertext_target);
    success &= eq;

    cout << "ENCRYPTION: " << endl
         << "   ciphertext target =" << '\t' << to_string(ciphertext_target) << endl
         << "   ciphertext test   =" << '\t' << to_string(ciphertext_test) << endl
         << "ENCRYPTION: " << (eq ? "SUCCESS" : "FAIL") << endl << endl;

    /* DECRYPTION CHECK */
    segment plaintext_test = decrypt<KEYSIZE>(ciphertext_test, master_key);
    segment plaintext_target = plaintext;

    eq = eqseg(plaintext_test, plaintext_target);
    success &= eq;

    cout << "DECRYPTION" << endl
         << "error at decryption" << endl
         << "   plaintext target  =" << '\t' << to_string(plaintext_target) << endl
         << "   plaintext test    =" << '\t' << to_string(plaintext_test) << endl
         << "DECRYPTION: " << (success ? "SUCCESS" : "FAIL") << endl << endl;

    return success;
}

void test_128mk(){
    cout << "CONSISTENCY WITH SPECIFICATION: 128bit master key" << endl
         << "--------------------------------------------" << endl;

    key128 master_key = to_segment<16>("0x000102030405060708090a0b0c0d0e0f");

    array<segment, 4> ws = {
        to_segment<16>("0x000102030405060708090a0b0c0d0e0f"),
        to_segment<16>("0x2afbea741e1746dd55c63ba1afcea0a5"),
        to_segment<16>("0x7c8578018bb127e02dfe4e78c288e33c"),
        to_segment<16>("0x6785b52b74da46bf181054082763ff6d")
    };

    array<segment, 13> encryption_keys = {
        to_segment<16>("0xd415a75c794b85c5e0d2a0b3cb793bf6"),
        to_segment<16>("0x369c65e4b11777ab713a3e1e6601b8f4"),
        to_segment<16>("0x0368d4f13d14497b6529ad7ac809e7d0"),
        to_segment<16>("0xc644552b549a263fb8d0b50906229eec"),
        to_segment<16>("0x5f9c434951f2d2ef342787b1a781794c"),
        to_segment<16>("0xafea2c0ce71db6de42a47461f4323c54"),
        to_segment<16>("0x324286db44ba4db6c44ac306f2a84b2c"),
        to_segment<16>("0x7f9fa93574d842b9101a58063771eb7b"),
        to_segment<16>("0xaab9c57731fcd213ad5677458fcfe6d4"),
        to_segment<16>("0x2f4423bb06465abada5694a19eb88459"),
        to_segment<16>("0x9f8772808f5d580d810ef8ddac13abeb"),
        to_segment<16>("0x8684946a155be77ef810744847e35fad"),
        to_segment<16>("0x0f0aa16daee61bd7dfee5a599970fb35")
    };

    array<segment, 13> decryption_keys = {
        to_segment<16>("0x0f0aa16daee61bd7dfee5a599970fb35"),
        to_segment<16>("0xccb3a0230b6dac1d53eef49d961aa57f"),
        to_segment<16>("0x60ea3252ac3ea9bc9ac78e79df20b5b5"),
        to_segment<16>("0x5794eadaece652f8a2ccbf68ee82a730"),
        to_segment<16>("0x468a335e49ec1db45d112aaf2109e5bf"),
        to_segment<16>("0x938ebbda880c6bb87fa01c97e68811a9"),
        to_segment<16>("0xbfda5018ab33d14cc538ea5c81bd1011"),
        to_segment<16>("0xb5a90e77d5b94bb56e47af759fcfa05e"),
        to_segment<16>("0x21a6c28c5e1175a4378cd34dd3195a83"),
        to_segment<16>("0x8d726063ca2ceddc92afb45dd7db643e"),
        to_segment<16>("0x27efd355eb17e90e5963c46515016f8d"),
        to_segment<16>("0xd000e81367819b077b0a657f6740e8e4"),
        to_segment<16>("0xd415a75c794b85c5e0d2a0b3cb793bf6")
    };

    segment ciphertext_target = to_segment<16>("0xd718fbd6ab644c739da95f3be6451778");

    bool success = test_consistency<16, 13>(master_key, ws, encryption_keys, decryption_keys, ciphertext_target);

    cout << "--------------------------------------------" << endl
         << "CONSISTENCY WITH SPECIFICATION: 128bit master key: " << (success ? "SUCCESS" : "FAIL") << endl << endl;
}

void test_192mk(){
    cout << "CONSISTENCY WITH SPECIFICATION: 192bit master key" << endl
         << "--------------------------------------------" << endl;

    key196 master_key = to_segment<24>("0x000102030405060708090a0b0c0d0e0f1011121314151617");

    array<segment, 4> ws = {
        to_segment<16>("0x000102030405060708090a0b0c0d0e0f"),
        to_segment<16>("0xe48c52301e91d991b649ed7bb7cde8ad"),
        to_segment<16>("0xa356ea6cafe4869797a1b4eea56d38cc"),
        to_segment<16>("0xe1898f2e0e626ccf1f58bd50713c93bb")
    };

    array<segment, 15> encryption_keys = {
        to_segment<16>("0xbd14be928e4305d5333b3cc231a278f6"),
        to_segment<16>("0x4395c65ac3dc4c6d269b1f8f81503c00"),
        to_segment<16>("0x3121965d9e01475bda385705b2c736eb"),
        to_segment<16>("0x40486f2e2e220c4fbf985c51507df23a"),
        to_segment<16>("0x6f9ad358cd1da267352ab928609ed4f8"),
        to_segment<16>("0xae5623a9583c0d48e980e054988e8170"),
        to_segment<16>("0x412fcd1b6cf798cb8b656d709bdc426c"),
        to_segment<16>("0xf99393300e6068c91752b15e612e87ad"),
        to_segment<16>("0x36c83fac72fcbb12b498804d0fdf353d"),
        to_segment<16>("0x167864adca3c7e88222330362231787f"),
        to_segment<16>("0x40bdfdc6a1c314e0eb90850b64a17555"),
        to_segment<16>("0x0088ae6f6fe3cd0eff589d1011bc337b"),
        to_segment<16>("0x0f49eecbdf21f0bad3effe5dfe4b2717"),
        to_segment<16>("0xb37e117bd54103e6e4ff711de6669d9b"),
        to_segment<16>("0xa467dc0b2048d83faf3ffd3355a9ff5b")
    };

    array<segment, 15> decryption_keys = {
        to_segment<16>("0xa467dc0b2048d83faf3ffd3355a9ff5b"),
        to_segment<16>("0x4dd0b9831c584a7f72e931dd8ede23f5"),
        to_segment<16>("0xb4a02c5b7e7cff4981137b76a1e8af63"),
        to_segment<16>("0xe58ecdefea05c868b394d7dabc7298b3"),
        to_segment<16>("0xdc94b739beef8d4acd30f3fb4bbd0a19"),
        to_segment<16>("0x518c97ed5d0bfaac5240e7f2dd6e2087"),
        to_segment<16>("0xa3cffeff0406d3f6fcce825184d8f470"),
        to_segment<16>("0xbab3d61669640fcd9fda3fd0cce02c65"),
        to_segment<16>("0x9fe831feae7e081014a882cd3f3396f3"),
        to_segment<16>("0x9ad65f61fd36b359f684ac037cc53668"),
        to_segment<16>("0x622efcce90b0b68380d667bfeee031ed"),
        to_segment<16>("0xa44f0daf2b4489a972d5971afdb359f2"),
        to_segment<16>("0x9777f3c8a450e691aed77bb2243af84e"),
        to_segment<16>("0x044b0b0eccb4bdfb37747a14e7512e75"),
        to_segment<16>("0xbd14be928e4305d5333b3cc231a278f6")
    };

    segment ciphertext_target = to_segment<16>("0x26449c1805dbe7aa25a468ce263a9e79");

    bool success = test_consistency<24, 15>(master_key, ws, encryption_keys, decryption_keys, ciphertext_target);

    cout << "--------------------------------------------" << endl
         << "CONSISTENCY WITH SPECIFICATION: 192bit master key: " << (success ? "SUCCESS" : "FAIL") << endl << endl;
}

void test_256mk(){
    cout << "CONSISTENCY WITH SPECIFICATION: 256bit master key" << endl
         << "--------------------------------------------" << endl;
    key256 master_key = to_segment<32>("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    array<segment, 4> ws = {
            to_segment<16>("0x000102030405060708090a0b0c0d0e0f"),
            to_segment<16>("0x15169e6ec54aaf0c975414fead1c71f3"),
            to_segment<16>("0x90ec92c2a800405af99389e9c88b4e62"),
            to_segment<16>("0xb68cd7a1ba16abee905f7009a8e968a9")
    };

    array<segment, 17> encryption_keys = {
            to_segment<16>("0x8e3f60a1d7c8deae5de898e18e92dbac"),
            to_segment<16>("0x7cdacc735712fa0c9f5f4bccdc2148e2"),
            to_segment<16>("0xbdf9a41332f477182cee5be2268a7b7f"),
            to_segment<16>("0x174d37a19a56cb6e309f910889a80928"),
            to_segment<16>("0x5a39e1e52e283ada829c541222a527f2"),
            to_segment<16>("0x840002abe4938a89c754944b5e3b6220"),
            to_segment<16>("0xc13e4391c519ef198dbede34e835ae71"),
            to_segment<16>("0xae96cbbfba14afe898557c07b8fb7cbf"),
            to_segment<16>("0x92eb809cd1a688396aabd9c6d4a45bee"),
            to_segment<16>("0x4a24ef53fc5bc6c0c54986a6f81c79f8"),
            to_segment<16>("0x42e77cc39d1d6d4fcf42131dffc99b1f"),
            to_segment<16>("0x578df6e0db970a2f705f5049c869c869"),
            to_segment<16>("0x62a455854faf0c785e8732f286864138"),
            to_segment<16>("0x4116be43b9836bf87311b3cfe56a3892"),
            to_segment<16>("0x4de7c735e02ff85e2de73dbd13cd25b2"),
            to_segment<16>("0x348e54a23e122eeb1659f70e28e9e9a8"),
            to_segment<16>("0xf37728567c61bca7affc62e88395a6bb")
    };

    array<segment, 17> decryption_keys = {
            to_segment<16>("0xf37728567c61bca7affc62e88395a6bb"),
            to_segment<16>("0xfd62e7342bfde4dbd9499dbb605b04bf"),
            to_segment<16>("0x0fddde54a27fd06456f6779dcf03c84d"),
            to_segment<16>("0xa1d0cf146ae42a0d5dad9e70003bdec0"),
            to_segment<16>("0xd8e599b24da2fa817d5093a776793345"),
            to_segment<16>("0xbfc0e457ae1820ff7e0efbbd80db257e"),
            to_segment<16>("0xec43f94c756c16adb2acd64b19b6c5d8"),
            to_segment<16>("0x80f83e941cc54e3630d40048da4028d7"),
            to_segment<16>("0xfbe497edad612923021e12d063a84f41"),
            to_segment<16>("0xe0fdffae2d79e75a524013b7f04991a8"),
            to_segment<16>("0x13e967b0fdd52624b97bedf6e9c0a883"),
            to_segment<16>("0x0ff5cf18dbcdaac866ea6cac40442506"),
            to_segment<16>("0x6dddbb6cd6ef2ef19466c369942c10fa"),
            to_segment<16>("0xfe0124176f59613ebf4fbb7dc11ae43f"),
            to_segment<16>("0x65d35c19276918ffc078ed2e183c1f93"),
            to_segment<16>("0x772cce8c5b4055fd75160b2faf0c9165"),
            to_segment<16>("0x8e3f60a1d7c8deae5de898e18e92dbac")
    };

    segment ciphertext_target = to_segment<16>("0xf92bd7c79fb72e2f2b8f80c1972d24fc");

    bool success = test_consistency<32, 17>(master_key, ws, encryption_keys, decryption_keys, ciphertext_target);

    cout << "--------------------------------------------" << endl
    << "CONSISTENCY WITH SPECIFICATION: 256bit master key: " << (success ? "SUCCESS" : "FAIL") << endl << endl;

}

template<int KEYSIZE, int N>
bool test_real(const array<array<uint8_t, KEYSIZE>, N> keys, 
        const array<segment, N> plaintexts)
{
    bool success = true;
    for(int i = 0; i < N; ++i){
        array<uint8_t, KEYSIZE> key = keys[i];
        segment plaintext = plaintexts[i];

        segment ciphertext = encrypt<KEYSIZE>(plaintext, key);
        segment result = decrypt<KEYSIZE>(ciphertext, key);

        bool eq = eqseg(plaintext, result);
        success &= eq;

        if (eq){
            cout << "SUCCESS" << endl;
            success &= true;
        }
        else{
            cout << "FAIL" << endl;
            success &= false;
        }

        cout << "   plaintext: " << '\t' << to_string(plaintext) << endl
             << "   result: " << '\t' << to_string(result) << endl;
    }

    return success;
}

void test_real_128(){
    cout << "REAL TEST CASES with 128 bit KEY" << endl
         << "--------------------------------------------" << endl;

    /* [key, plaintext] */
    array<key128, 4> keys = {
        to_segment<16>("0x00112233445566778899aabbccddeeff"),
        to_segment<16>("0x128a8d8f8e263197239e123997c73d13"),
        to_segment<16>("0x231122232344526623abbc2efffeeaaa"),
        to_segment<16>("0x231122232344526623abbc2efffeeaaa")
    };
    array<segment, 4> plaintexts = {
        to_segment<16>("0x11111111aaaaaaaa11111111bbbbbbbb"),
        to_segment<16>("0x1002100308150d08310a089bc02c3333"),
        to_segment<16>("0xeeeeee33333cc3cc33ffedac2cc11111"),
        to_segment<16>("0xeeeeee33333cc3cc33ffedac2cc11111")
    };

    bool success = test_real<16,4>(keys, plaintexts);

    cout << "--------------------------------------------" << endl
         << "REAL TEST CASES: " << (success ? "SUCCESS" : "FAIL") << endl << endl;
}


void test_real_192(){
    cout << "REAL TEST CASES with 192 bit KEY" << endl
         << "--------------------------------------------" << endl;

    /* [key, plaintext] */
    array<key196, 4> keys = {
        to_segment<24>("0x000102030405060708090a0b0c0d0e0f1011121314151617"),
        to_segment<24>("0x128a8d8f8e263197239e123997c73d13122b7a5f20e15d5f"),
        to_segment<24>("0x231122232344526623abbc2efffeeaaabbbcccdddeeefffg"),
        to_segment<24>("0x231122232344526623abbc2efffeeaaabbbcccdddeeefffg")
    };
    array<segment, 4> plaintexts = {
    	to_segment<16>("0x11111111aaaaaaaa11111111bbbbbbbb"),
    	to_segment<16>("0x1002100308150d08310a089bc02c3333"),
    	to_segment<16>("0xeeeeee33333cc3cc33ffedac2cc11111"),
    	to_segment<16>("0xeeeeee33333cc3cc33ffedac2cc11111")
    };

    bool success = test_real<24, 4>(keys, plaintexts);

    cout << "--------------------------------------------" << endl
         << "REAL TEST CASES: " << (success ? "SUCCESS" : "FAIL") << endl << endl;
}

void test_real_256(){
    cout << "REAL TEST CASES with 256 bit KEY" << endl
             << "--------------------------------------------" << endl;
    
    array<key256, 4> keys ={
            to_segment<32>("0xa6af4645131396666d30d55f68f5d097636a9b0be1e775de20ef63eccd19da04"),
            to_segment<32>("0xe6e71e2ff1676458437a756338c02c4023841a31ba81ed9200d763a9b69e2ee5"),
            to_segment<32>("0x16921c3c6be48779840e7b731014ef9f6227e5351199902143fce6ff6035fc45"),
            to_segment<32>("0xe6cdc02d1b6ac9b0caca0b97bdcb90087d53d70e269ef4fbfb5f7f62c2d53eda")
    };

    array<segment, 4> plaintexts ={
            to_segment<16>("0x0bf560b43e1dcebe9cae8868aa572562"),
            to_segment<16>("0x057663b91c6ea1c3d625f8e923158778"),
            to_segment<16>("0xdff32ac362113d404653e3c16d6e5d72"),
            to_segment<16>("0xc65e012633761c652b81f42528475b92")
    };
    
    bool success = test_real<32, 4>(keys, plaintexts);

    cout << "-------------------------" << endl;
    cout << "REAL TEST CASES: " << (success ? "SUCCESS" : "FAIL") << endl << endl;
}


int main(){
    /* BASIC TESTS */
    test_circular_rotation();

    /* SPECIFICATION PROVIDED TESTS */
    test_128mk();
    test_192mk();
    test_256mk();

    /* REAL TESTS CASES */
    test_real_128();
    test_real_192();
	
	test_real_256();
    return 0;
}
