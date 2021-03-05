#include <iostream>
#include <fstream>
#include <iomanip>
#include "anubis.h"

//#define ENABLE_TEST

#ifdef ENABLE_TEST
void create_random_filled_file(std::string fname, size_t size);
bool files_are_equal(std::string fname1, std::string fname2);
#endif // ENABLE_TEST

std::vector<crypto::byte> open_key(std::string fname);
void save_key(std::string fname, std::vector<crypto::byte> key);

using namespace crypto;

int main(int argc, char* argv[])
{
#ifdef ENABLE_TEST
	std::string f1_resource = "tests_data/data1.dt";
	std::string f2_resource = "tests_data/data2.dt";
	std::string f3_resource = "tests_data/data3.dt";
	std::string fpdf_resource = "tests_data/book.pdf";

	create_random_filled_file(f1_resource, 0);
	create_random_filled_file(f2_resource, 16 * 1024 * 32 / 3);
	create_random_filled_file(f3_resource, 16 * 1024);

	anubis cypher;
	auto f1 = cypher.decrypt_file(cypher.encrypt_file(f1_resource));
	auto f2 = cypher.decrypt_file(cypher.encrypt_file(f2_resource));
	auto f3 = cypher.decrypt_file(cypher.encrypt_file(f3_resource));

	cypher.set_file_buf_sz(cypher.get_file_buf_sz() * 11 / 3);

	auto key = anubis::generate_random_key(8);
	cypher.set_key(key);

	auto fpdf = cypher.decrypt_file(cypher.encrypt_file(fpdf_resource));

	if (files_are_equal(f1, f1_resource)) std::cout << "TEST1: OK." << std::endl;
	else std::cout << "TEST1: FAILED." << std::endl;

	if (files_are_equal(f2, f2_resource)) std::cout << "TEST2: OK." << std::endl;
	else std::cout << "TEST2: FAILED." << std::endl;

	if (files_are_equal(f3, f3_resource)) std::cout << "TEST3: OK." << std::endl;
	else std::cout << "TEST3: FAILED." << std::endl;

	if (files_are_equal(fpdf, fpdf_resource)) std::cout << "TESTPDF: OK." << std::endl;
	else std::cout << "TESTPDF: FAILED." << std::endl;
#endif // ENABLE_TEST
	std::cout << "Starting..." << std::endl;
	std::string way_to_prog(argv[0]);
	size_t pos = way_to_prog.find_last_of('\\');

	std::string prog_name(
		way_to_prog.begin() + (pos == std::string::npos ? 0 : pos + 1),
		way_to_prog.end()
	);

	std::cout << "Checking arguments..." << std::endl;
	if (argc == 1 || argc > 4)
	{
		std::cout << "Wrong arguments count!\n"
			<< "Usage: " + prog_name + " -enc|-dec data_file_name key_file_name" << std::endl;
		return -1;
	}


	if (strcmp(argv[1], "-enc") == 0)
	{
		std::cout << "Encryption..." << std::endl;
		anubis cypher;
		try
		{
			auto f_res = cypher.encrypt_file(argv[2]);
			
			save_key(std::string(argv[3]) + ".key", cypher.get_key());

			std::cout << "Encrypted.\nFile saved as: "
				<< f_res << std::endl;
			std::cout << "Key saved as: "
				<< std::string(argv[3]) + ".key" << std::endl;
			return 0;
		}
		catch (std::runtime_error & e)
		{
			std::cout << "Exception catched." << std::endl;
			std::cout << e.what() << std::endl;
			return -1;
		}
		catch (...)
		{
			std::cout << "Encryption error.\n"
				<< "You may have entered the file name incorrectly"
				<< " or it is already encrypted." << std::endl;
		}

		return -1;
	}

	if (strcmp(argv[1], "-dec") == 0)
	{
		std::cout << "Decryption..." << std::endl;
		anubis cypher;
		
		try 
		{
			auto loaded_key = open_key(argv[3]);
			cypher.set_key(loaded_key);
		} 
		catch (std::runtime_error & e)
		{
			std::cout << "Exception catched." << std::endl;
			std::cout << e.what() << std::endl;
			return -1;
		}
		catch (...)
		{
			return -1;
		}

		try
		{
			auto f_res = cypher.decrypt_file(argv[2]);

			std::cout << "Decrypted. File saved as: "
				<< f_res << std::endl;
			return 0;
		}
		catch (std::runtime_error & e)
		{
			std::cout << "Exception catched." << std::endl;
			std::cout << e.what() << std::endl;
			return -1;
		}
		catch (...) 
		{
			std::cout << "Decryption error.\n"
				<< "You may have entered the file name incorrectly"
				<< " or it is already decrypted." << std::endl;
		}
		return -1;
	}

	std::cout << "Wrong arguments!\n"
		<< "Usage: " + prog_name + " -enc|-dec data_file_name key_file_name" << std::endl;

	return -1;
}


#ifdef ENABLE_TEST
void create_random_filled_file(std::string fname, size_t size)
{
	std::ofstream file(fname, std::ios_base::trunc | std::ios_base::binary);
	std::random_device rd;
	std::mt19937_64 generator(rd());
	std::uniform_int_distribution<int32_t> distribution;

	std::vector<char> data(size);
	std::generate(data.begin(), data.end(),
		[&distribution, &generator]() { return distribution(generator); });

	file.write(const_cast<const char*>(data.data()), data.size());
	file.close();
}

bool files_are_equal(std::string fname1, std::string fname2)
{
	std::ifstream f1(fname1, std::ios_base::binary);
	std::ifstream f2(fname2, std::ios_base::binary);

	f1.seekg(0, std::ios::end);
	f2.seekg(0, std::ios::end);
	std::streampos s1 = f1.tellg(), s2 = f2.tellg();
	f1.seekg(0, std::ios::beg);
	f2.seekg(0, std::ios::beg);

	if (s1 != s2) 
	{
		return false;
	}

	size_t buf_sz = 64 * 1024;

	while (!f1.eof()) 
	{
		std::vector<char> dt1(buf_sz);
		std::vector<char> dt2(buf_sz);

		f1.read(dt1.data(), buf_sz);
		f2.read(dt2.data(), buf_sz);

		if (dt1 != dt2) 
		{
			return false;
		}
	}

	return true;
}
#endif // ENABLE_TEST

std::vector<crypto::byte> open_key(std::string fname)
{
	std::cout << "Trying to load key..." << std::endl;
	std::ifstream fin(fname, std::ios_base::binary);
	if (!fin.is_open())
	{
		throw std::runtime_error("Unable to open the \"" + fname + "\" file.");
	}

	fin.seekg(0, std::ios::end);
	size_t sz = 
		fin.tellg() > 256 ? 
		static_cast<size_t>(80) : static_cast<size_t>(fin.tellg());
	fin.seekg(0, std::ios::beg);

	std::vector<crypto::byte> key(sz);

	fin.read(reinterpret_cast<char*>(key.data()), sz);

	fin.close();
	return key;
}

void save_key(std::string fname, std::vector<crypto::byte> key)
{
	std::cout << "Saving key..." << std::endl;
	std::ofstream fout(fname, std::ios_base::binary);

	fout.write(reinterpret_cast<char*>(key.data()), key.size());

	fout.close();
}
