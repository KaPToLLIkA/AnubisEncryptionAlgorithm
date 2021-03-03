#include <iostream>
#include <fstream>
#include <iomanip>
#include "anubis.h"


void create_random_filled_file(std::string fname);

using namespace crypto;

int main() 
{
	std::vector<byte> key(40, '\0');
	anubis a(key);

#ifdef _DEBUG
	auto enc = a.get_round_encrypt_key();
	auto dec = a.get_round_decrypt_key();

	std::cout << "DEC\n";
	for (auto key : dec) 
	{
		std::cout
			<< std::setw(16) << key[0]
			<< std::setw(16) << key[1]
			<< std::setw(16) << key[2]
			<< std::setw(16) << key[3] << std::endl;
	}

	std::cout << "ENC\n";
	for (auto key : enc)
	{
		std::cout
			<< std::setw(16) << key[0]
			<< std::setw(16) << key[1]
			<< std::setw(16) << key[2]
			<< std::setw(16) << key[3] << std::endl;
	}
#endif // _DEBUG

	return 0;
}

void create_random_filled_file(std::string fname)
{
	std::ofstream file(fname, std::ios_base::trunc | std::ios_base::binary);
	std::random_device rd;
	std::mt19937_64 generator(rd());
	std::uniform_int_distribution<int32_t> distribution;
	
	std::vector<char> data(16 * 1024);
	std::generate(data.begin(), data.end(),
		[&distribution, &generator]() { return distribution(generator); });

	file.write(const_cast<const char*>(data.data()), data.size());
	file.close();
}
