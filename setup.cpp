#include <fstream>
#include <sstream>
#include <sys/time.h>
#include "seal/seal.h"
#include "timer.hpp"

using namespace std;
using namespace seal;
auto timer = mytimer::timer();

inline void print_parameters(std::shared_ptr<seal::SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw std::invalid_argument("context is not set");
    }
    auto &context_data = *context->key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " <<
        context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_mod_count = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::BFV)
    {
        std::cout << "|   plain_modulus: " << context_data.
            parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

int main(int argc, char **argv)
{
    cout << "Setting up FHE" << endl;
    timer.set();

    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    vector <int> poly_mod_vec (7, 40);
    poly_mod_vec.push_back(60);
    poly_mod_vec.insert(poly_mod_vec.begin(), 1, 60);
    //{ 50, 30, 30, 30, 50 }
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, poly_mod_vec));

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();

    timer.print("Finished setting up FHE: ");

    cout << "Saving the generated keys..." << endl;
    ofstream parmsFile("keys/params.bin",ios::binary);
    EncryptionParameters::Save(parms, parmsFile);
    parmsFile.close();

    ofstream pkFile("keys/pk.bin",ios::binary);
    public_key.save(pkFile);
    pkFile.close();

    ofstream skFile("keys/sk.bin",ios::binary);
    secret_key.save(skFile);
    skFile.close();

    ofstream galFile("keys/gk.bin",ios::binary);
    gal_keys.save(galFile);
    galFile.close();

    ofstream relinFile("keys/rk.bin", ios::binary);
    relin_keys.save(relinFile);
    relinFile.close();

    cout << "Finished" << endl;
    
    return 0;

}