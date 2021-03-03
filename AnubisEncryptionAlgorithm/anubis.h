#pragma once
#include <array>
#include <vector>
#include <random>
#include <cassert>
#include <string>

namespace crypto {

#define ANUBIS_BLOCK_SZ 16
#define GET_BYTE(b32, shift) (byte(b32 >> shift))

	typedef uint8_t byte;
	typedef std::array<byte, ANUBIS_BLOCK_SZ> block8_t;
	typedef std::array<uint32_t, ANUBIS_BLOCK_SZ / 4> block32_t;

	class anubis
	{
		static uint32_t T0[256];
		static uint32_t T1[256];
		static uint32_t T2[256];
		static uint32_t T3[256];
		static uint32_t T4[256];
		static uint32_t T5[256];

		

		std::vector<byte> key;
		std::vector<block32_t> round_encrypt_key;
		std::vector<block32_t> round_decrypt_key;

		block32_t generate_random_iv();

	public:
		static std::vector<byte> generate_random_key(int32_t N);
		

		explicit anubis();
		explicit anubis(std::vector<byte>& key);

		void set_key(std::vector<byte>& key);
		std::vector<byte> get_key();



#ifdef _DEBUG
		std::vector<block32_t> get_round_encrypt_key();
		std::vector<block32_t> get_round_decrypt_key();
#endif // _DEBUG


	};

} // end namespace crypto