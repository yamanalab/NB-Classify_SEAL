#include <fstream>
#include <sstream>
#include <sys/time.h>
#include "tools.h"
#include "seal/seal.h"
#include "timer.hpp"

using namespace std;
using namespace seal;

auto timer = mytimer::timer();

int main(int argc, char **argv){

    cout << "Setting FHE..." << endl;
    ifstream paramsFile("keys/params.bin");
    EncryptionParameters params(scheme_type::CKKS);
    params = EncryptionParameters::Load(paramsFile);
    auto context = SEALContext::Create(params);
    paramsFile.close();

    PublicKey public_key = loadPK("keys/pk.bin");

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);

    CKKSEncoder encoder(context);
    size_t num_slots = encoder.slot_count();
    cout << "Number of slots: " << num_slots << endl;

    double scale = pow(2.0, 40);

    //////////////////////////////////////////////////////////////////////////

    cout << "Reading model" << endl;

    cout << "Please input the name of your dataset: ";
    string dataset;
    cin >> dataset;

    string info_filename = "datasets/"+dataset+"_info.csv";
    Info info = readInfo(info_filename);
    cout << "Finished reading in the information on the dataset" << endl;

    string model_filename = "datasets/"+dataset+"_model.csv";
    Model NB = readModel(model_filename, info.class_names, info.attr_values);
    cout << "Finished reading in the plaintext model" << endl;
    //printModel(NB);

    int class_num = NB.class_num;
    int num_probs = info.num_features + 1;
    int num_data = num_slots/num_probs;

    for (int i=0; i<class_num; i++){
        timer.set();

        vector <double> temp = NB.probs[i];
        for (int j=0; j<num_data-1; j++){
            temp.insert(temp.end(), NB.probs[i].begin(), NB.probs[i].end());
        }
        temp.resize(num_slots);

        Plaintext cur;
        encoder.encode(temp, scale, cur);
        Ciphertext ctxt;
        encryptor.encrypt(cur, ctxt);

        double encTime = timer.get();
        //myfile << encTime << "," << decTime << "\n"<< flush;
        
        string filename = "model/"+dataset+"_class"+to_string(i)+".bin";
        writeCtxt(filename, ctxt);
    }

    cout << "Finished encrypting and writing out the model" << endl;
    cout << endl;
    
    return 0;
}