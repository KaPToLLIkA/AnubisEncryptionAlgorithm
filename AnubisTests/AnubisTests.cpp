#include "pch.h"
#include "CppUnitTest.h"
#include "../AnubisEncryptionAlgorithm/anubis.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace AnubisTests
{
	TEST_CLASS(AnubisTests)
	{
	public:
		
		TEST_METHOD(testInstanceCreationAndSetKey)
		{
			using namespace crypto;
			std::vector<byte> key(16, 'X');
			
			anubis cypher1;
			cypher1.set_key(key);
			anubis cypher2(key);


			bool keys_equal = (cypher1.get_key() == cypher2.get_key());
#ifdef _DEBUG
			bool round_keys_enc_equal =
				(cypher1.get_round_encrypt_key() == cypher2.get_round_encrypt_key());
			bool round_keys_dec_equal =
				(cypher1.get_round_decrypt_key() == cypher2.get_round_decrypt_key());
			Assert::AreEqual(true, round_keys_dec_equal);
			Assert::AreEqual(true, round_keys_enc_equal);
#endif // _DEBUG
			Assert::AreEqual(true, keys_equal);
			
		}

		TEST_METHOD(testDataEncryptionDecription)
		{
			using namespace crypto;
			anubis cypher;

			std::vector<byte> data(301, 'B');

			auto data2 = cypher.decrypt(cypher.encrypt(data));
			bool success_data_enc_dec = (data == data2);

			Logger::WriteMessage(std::string(std::to_string(data.size()) + " << data len\n").c_str());
			Logger::WriteMessage(std::string(std::to_string(data2.size()) + " << data2 len").c_str());
			Assert::AreEqual(true, success_data_enc_dec);
		}

		//no data
		TEST_METHOD(testDataEncryptionDecriptionStress1)
		{
			using namespace crypto;
			anubis cypher;

			std::vector<byte> data(0, 'B');

			auto data2 = cypher.decrypt(cypher.encrypt(data));
			bool success_data_enc_dec = (data == data2);

			Logger::WriteMessage(std::string(std::to_string(data.size()) + " << data len\n").c_str());
			Logger::WriteMessage(std::string(std::to_string(data2.size()) + " << data2 len").c_str());
			Assert::AreEqual(true, success_data_enc_dec);
		}

		//small data
		TEST_METHOD(testDataEncryptionDecriptionStress2)
		{
			using namespace crypto;
			anubis cypher;

			std::vector<byte> data(1, 'B');

			auto data2 = cypher.decrypt(cypher.encrypt(data));
			bool success_data_enc_dec = (data == data2);

			Logger::WriteMessage(std::string(std::to_string(data.size()) + " << data len\n").c_str());
			Logger::WriteMessage(std::string(std::to_string(data2.size()) + " << data2 len").c_str());
			Assert::AreEqual(true, success_data_enc_dec);
		}

		//very big data
		TEST_METHOD(testDataEncryptionDecriptionStress3)
		{
			using namespace crypto;
			anubis cypher;

			std::vector<byte> data(1046527, 'B');

			auto data2 = cypher.decrypt(cypher.encrypt(data));
			bool success_data_enc_dec = (data == data2);

			Logger::WriteMessage(std::string(std::to_string(data.size()) + " << data len\n").c_str());
			Logger::WriteMessage(std::string(std::to_string(data2.size()) + " << data2 len").c_str());
			Assert::AreEqual(true, success_data_enc_dec);
		}

	};
}
