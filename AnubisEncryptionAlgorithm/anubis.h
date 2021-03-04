#pragma once
#include <array>
#include <vector>
#include <random>
#include <cassert>
#include <string>
#include <fstream>

namespace crypto {

#define ANUBIS_BLOCK_SZ 16
#define GET_BYTE(b32, shift) (byte(b32 >> shift))

	typedef uint8_t byte;
	typedef std::array<uint32_t, ANUBIS_BLOCK_SZ / 4> block32_t;

	block32_t operator^(const block32_t& a, const block32_t& b);
	std::vector<byte>& operator+(const std::vector<byte>& a, const block32_t& b);

	class anubis
	{
		static uint32_t T0[256];
		static uint32_t T1[256];
		static uint32_t T2[256];
		static uint32_t T3[256];
		static uint32_t T4[256];
		static uint32_t T5[256];

		static std::vector<block32_t> split_data(std::vector<byte> data, bool is_last_block = true);
		
		uint32_t file_buf_sz = ANUBIS_BLOCK_SZ * 8 * 25; //in bytes
		std::vector<byte> key;
		std::vector<block32_t> round_encrypt_key;
		std::vector<block32_t> round_decrypt_key;

		block32_t generate_random_iv();
		block32_t crypt(block32_t block, std::vector<block32_t>& round_keys);

	public:
		static std::vector<byte> generate_random_key(int32_t N);

		explicit anubis();
		explicit anubis(std::vector<byte>& key);

		void set_key(std::vector<byte>& key);
		std::vector<byte> get_key();

		void set_file_buf_sz(uint32_t sz);
		uint32_t get_file_buf_sz();

		std::vector<byte> encrypt(std::vector<byte>* data);
		std::vector<byte> encrypt(std::vector<byte> data);
		std::vector<byte> decrypt(std::vector<byte>* data);
		std::vector<byte> decrypt(std::vector<byte> data);

		bool encrypt_file(std::string* fname);
		bool encrypt_file(std::string fname);
		bool decrypt_file(std::string* fname);
		bool decrypt_file(std::string fname);

#ifdef _DEBUG
		std::vector<block32_t> get_round_encrypt_key();
		std::vector<block32_t> get_round_decrypt_key();
#endif // _DEBUG


	};

} // end namespace crypto