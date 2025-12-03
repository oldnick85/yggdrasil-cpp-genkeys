#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

#include "../../src/compare.h"
#include "../../src/ed25519_keys.h"
#include "../../src/ed25519_keys_generator.h"

using namespace yggdrasil_cpp_genkeys;

struct TestKeys
{
    std::string secret_hex;
    std::string public_hex;
    std::string ipv6_hex;
};

std::vector<TestKeys> test_data = {
    {"ef04f3926ed9959d407ab2c14c04fe4742cdf833bad31ea8c797b6ee10e7a5e2c14f47307"
     "e7b1a45df5ba772fe1f36249996df3cd346e192f0e9eff49fa4c506",
     "c14f47307e7b1a45df5ba772fe1f36249996df3cd346e192f0e9eff49fa4c506",
     "200:7d61:719f:309:cb74:4148:b11a:3c1"},
    {"9637c64de3d10267da878639fb1a0fdf4780e9a0c0ccdb09d00bfe1a826957dd22e5d58fd"
     "303e03f53afaea60bfc3aa7399451a7f93a4b0cb64cebb37486a5f4",
     "22e5d58fd303e03f53afaea60bfc3aa7399451a7f93a4b0cb64cebb37486a5f4",
     "202:e8d1:5381:67e0:fe05:6282:8acf:a01e"},
    {"0ed9606e036b5f98c5dc75ea1515ce7fd4e8334d1410ab0277f20ff1f440ec100abe528a5"
     "43de22692585544283aaaa12fb8986b6b8ce1c79621806c595d234d",
     "0abe528a543de22692585544283aaaa12fb8986b6b8ce1c79621806c595d234d",
     "204:a835:aeb5:7843:bb2d:b4f5:577a:f8aa"},
    {"f668b7b652c128957630ed2cfb1ab49d1eddc69f300f3a779e7da6f5ea6c02040797da333"
     "a28364fa0bb2628e729ccbca5cfb56e67d50ea1b5d525a5d127ebbb",
     "0797da333a28364fa0bb2628e729ccbca5cfb56e67d50ea1b5d525a5d127ebbb",
     "205:1a09:7331:75f2:6c17:d136:75c6:358c"},
    {"cd78726c405ab81d1bf57e79ea30b19b608a4728c9d2d71e31bb8ca0ce49da4404b75fe32"
     "ffcb55577968c8f42c30b371d06dd90a4e536a9ebd5fec15b31d650",
     "04b75fe32ffcb55577968c8f42c30b371d06dd90a4e536a9ebd5fec15b31d650",
     "205:d228:734:d2:aaa2:1a5c:dc2f:4f3d"},
    {"67d7724bde90c131ddead5bb742934ca03b9932b4a05fd1e0229a9686b7c19d30119c59c4"
     "57c25c89e0f83401bc85b45753fcf1e0d23d671df908dd7846da6d9",
     "0119c59c457c25c89e0f83401bc85b45753fcf1e0d23d671df908dd7846da6d9",
     "207:e63a:63ba:83da:3761:f07c:bfe4:37a4"},
    {"3243d7a38b7e187abdbc9322388a699d111cf82b265e1bb9e6e50acdeb1b90270045e6aa0"
     "bdc20de7f36db2b9b1cae54acb12a2044bd8885523a1106dcb012c7",
     "0045e6aa0bdc20de7f36db2b9b1cae54acb12a2044bd8885523a1106dcb012c7",
     "209:e865:57d0:8f7c:8603:2493:5193:8d46"},
    {"bf65b40a891e0143f28068be7fd049f985e1ee6289927d1b00e2df8790e8a80a0032d8213"
     "4ffb57b33bc2e895f3e47ef58004f46b36ea85cf7b8d44a27f0d2b8",
     "0032d82134ffb57b33bc2e895f3e47ef58004f46b36ea85cf7b8d44a27f0d2b8",
     "20a:693e:f658:254:2662:1e8b:b506:dc0"},
    {"daab84b6aeff19ae3699fb1849d7db7043832d2dce5a3a4052f2e80c30c93a6e00250400e"
     "57091276c19ec59d63b142ecb40777f17f6d991f470a4e4b80cd2f4",
     "00250400e57091276c19ec59d63b142ecb40777f17f6d991f470a4e4b80cd2f4",
     "20a:d7df:f8d4:7b76:c49f:309d:314e:275e"},
    {"68857c1e98b8efbad8d59016f92c1ddabadccd39bdf79a7f75bd6fe971a961c700018cc01"
     "6d1209a76cce26cc9dabcdbb0b1804cc2d5760658e92c936a05714f",
     "00018cc016d1209a76cce26cc9dabcdbb0b1804cc2d5760658e92c936a05714f",
     "20f:733f:e92e:df65:8933:1d93:3625:4324"},
    {"c2bc125f6dadb694d0d75ccfdd45a3b47f09a1e766541686d029671ed5e675e80000f9544"
     "d6c8a7af736099520a047d475008a4a503fc9b7447fc55bc3a0784f",
     "0000f9544d6c8a7af736099520a047d475008a4a503fc9b7447fc55bc3a0784f",
     "210:d57:6526:eb0a:1193:ecd5:bebf:7057"},
    {"cd284fe4acb7f3c3408041dc490a02d4b0f00bf9ecedd4e31dff2a9ec6e764d50000ef112"
     "8c608749751063ce4076fb7c24acb9b26957f1b19c6ed002dd7c012",
     "0000ef1128c608749751063ce4076fb7c24acb9b26957f1b19c6ed002dd7c012",
     "210:21dd:ae73:ef16:d15d:f386:37f1:2090"},
    {"f7860422730fc5da3903f9d808ec19fe17057ad40bcc702c3e85b784622b712e000081405"
     "784799cace422014817a8e21109774eded99266d83851b08ca40b4d",
     "000081405784799cace422014817a8e21109774eded99266d83851b08ca40b4d",
     "210:fd7f:50f7:cc6:a637:bbfd:6fd0:ae3b"},
    {"ce6af9a4d25ef85e69ad3e4385ab599ded9eebcb2e3e78fb6667c2c8f66584fa000046c52"
     "5cf837e4fd0686c01a83907723283e90a4076c740088a827e8cee05",
     "000046c525cf837e4fd0686c01a83907723283e90a4076c740088a827e8cee05",
     "211:e4eb:68c1:f206:c0be:5e4f:f95f:1be2"},
    {"cf60fb9ead5af816e3ee03fa0f4c246c2d1e4ad1ed0d248174a4076e3f2d686d000029fee"
     "f95abcd6bb9175dacf02029fd859aee0296b3fed10dc05034a5b32a",
     "000029feef95abcd6bb9175dacf02029fd859aee0296b3fed10dc05034a5b32a",
     "212:b008:8352:a194:a237:4512:987e:feb0"},
    {"b96c9de947c031e3116bc99cb0f9fae9e0bbf5787c23eef3901541132b9cf6da000018c0e"
     "3588a5b31b91786fbb8484306e37a9ddec05fe0a11facc5d5f75c95",
     "000018c0e3588a5b31b91786fbb8484306e37a9ddec05fe0a11facc5d5f75c95",
     "213:73f1:ca77:5a4c:e46e:8790:447b:7bcf"},
    {"a2c41919e4b7bdc15f2da66941a6c013f60d6685e97d30bf2724c18e6e1d849c000005a10"
     "b587db1d8ce75cf8d8f4988362069ec411f751a6a15f5b030911ea6",
     "000005a10b587db1d8ce75cf8d8f4988362069ec411f751a6a15f5b030911ea6",
     "215:97bd:29e0:9389:cc62:8c1c:9c2d:9df2"}};

TEST(yggdrasil_cpp_getkeys, keys_generation)
{
    Ed25519_KeysGenerator gen;
    for (auto& test_sample : test_data) {
        Seed_t seed;
        seed.FromHex(test_sample.secret_hex.substr(0, 64));
        gen.Generate(seed);
        ASSERT_EQ(gen.Keys().secret_key.ToHex(), test_sample.secret_hex);
        ASSERT_EQ(gen.Keys().public_key.ToHex(), test_sample.public_hex);
        const auto addr = AddrForKey(gen.Keys().public_key);
        ASSERT_EQ(addr.ToString(), test_sample.ipv6_hex);
    }
}

TEST(yggdrasil_cpp_getkeys, hex)
{
    const std::array<uint8_t, 7> bytes = {0x12, 0x34, 0x56, 0x78,
                                          0x90, 0xab, 0xcd};
    const auto hex = BytesToHex(bytes);
    ASSERT_EQ(hex.length(), 14);
    ASSERT_EQ(hex, "1234567890abcd");
    const std::array<uint8_t, 7> bytes_re = HexToBytes<7>(hex);
    ASSERT_EQ(bytes, bytes_re);
}

TEST(yggdrasil_cpp_getkeys, compare)
{
    PublicKey_t key1;
    key1.FromHex(
        "000000209962eff00defc3fcde53a526f5ed331c7461e3aa3b7a33c020eb8af2");
    PublicKey_t key2;
    key2.FromHex(
        "00000034b94aa677c962c41441781ed9b1fb5b45f2b219326d5831485f1a64f9");
    ASSERT_FALSE(IsBetter(key1, key2));
    key2.FromHex(
        "00000044b94aa677c962c41441781ed9b1fb5b45f2b219326d5831485f1a64f9");
    ASSERT_TRUE(IsBetter(key1, key2));
}
