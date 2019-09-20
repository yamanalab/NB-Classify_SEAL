#include <fstream>
#include <sstream>
#include <sys/time.h>
#include "tools.h"
#include "seal/seal.h"
#include "timer.hpp"

using namespace std;
using namespace seal;

auto timer = mytimer::timer(); //for measuring computation time

int main(int argc, char **argv)
{
    cout << "Setting up FHE" << endl;
    timer.set();

    ifstream paramsFile("keys/params.bin");
    EncryptionParameters params(scheme_type::CKKS);
    params = EncryptionParameters::Load(paramsFile);
    auto context = SEALContext::Create(params);
    paramsFile.close();

    double scale = pow(2.0, 40);

    PublicKey public_key = loadPK("keys/pk.bin");
    SecretKey secret_key = loadSK("keys/sk.bin");
    GaloisKeys gal_keys = loadGK("keys/gk.bin");
    RelinKeys relin_keys = loadRK("keys/rk.bin");

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t num_slots = encoder.slot_count();
    cout << "Number of slots: " << num_slots << endl;

    ///////////////////////////////////////////////////////////////////////

    cout << "Please input the name of your test dataset" << endl;
    string file;
    cin >> file;

    int pos = file.find("_");
    string dataset = file.substr(0, pos);
    cout << dataset << endl;

    cout << "Reading model" << endl;

    string info_filename = "datasets/"+dataset+"_info.csv";
    Info info = readInfo(info_filename);
    cout << "Finished reading in the information on the dataset" << endl;

    int flag = 0;
    int class_num;
    while (flag==0){
        cout << "Input number of classes: ";
        cin >> class_num;
        if (class_num <= info.class_num) flag=1;
        else{
            cout << "Invalid class number!" << endl;
            cout << "Please input a number less than or equal to " << info.class_num << endl;
        };
    }

    //reading in the encrypted classification model
    vector <Ciphertext> model_ctxts;
    for (int i=0; i<class_num; i++){
        string model_filename = "model/"+dataset+"_class"+to_string(i)+".bin";
        Ciphertext ctxt = loadCtxt(model_filename, context);
        model_ctxts.push_back(ctxt);
    }

    cout << endl;

    ////////////////////////////////////////////////////////////////////////////

    
    cout << "Reading data" << endl;
    string test_filename = "datasets/"+file+"_test.csv";
    vector <vector <string> > orig_data = readData(test_filename);
    cout << "Finished reading in data" << endl;

    //parsing data 
    vector <vector <double> > data;
    for (int i=0; i<orig_data.size(); i++){
        vector <double> temp = {1};
        vector <double> temp2 = parseData(orig_data[i], info.attr_values);
        temp.insert(temp.end(), temp2.begin(), temp2.end());
        temp.resize(num_slots);
        data.push_back(temp);
    }
    cout << "Finished processing data" << endl;
    cout << endl;

    ////////////////////////////////////////////////////////////////////////////

    string filename = "results/classifySingle_"+dataset+to_string(class_num)+".csv";
    ofstream myfile;
    myfile.open(filename);

    string filename2 = "results/result.txt";
    ofstream myfile2;
    myfile2.open(filename2);

    //int num = 1;
    int num = data.size();
    for (int i = 0; i<num; i++){
        timer.set();

        cout << "Classifying data " << i << endl;

        // Client generating the query by encrypting data and generating a permutation vector
        Plaintext cur;
        encoder.encode(data[i], scale, cur);
        Ciphertext ct_data;
        encryptor.encrypt(cur, ct_data);

        vector <long> perm_vec = genPermVec(class_num);
        printVector(perm_vec);
        // Client sends ct_data and perm_vec to the CS as a query

        //Upon receiving the query, the CS computes the below code
        //calculate the probability for each class
        vector <Ciphertext> res_ctxts;
        for (int j=0; j<class_num; j++){
            Ciphertext res = model_ctxts[j];
            //timer.set();
            evaluator.multiply_inplace(res, ct_data);
            evaluator.relinearize_inplace(res, relin_keys);
            evaluator.rescale_to_next_inplace(res);

            //timer.set();
            sumAll(evaluator, res, gal_keys, num_slots);
            //double cTime = timer.get();
            //myfile << cTime << "\n" << flush;
            res_ctxts.push_back(res);
        }
        cout << "Finished calculating probability of each class" << endl;

        
        //The CS permutes the vector of ciphertexts to blind the real index
        cout << "Permuting the probability ciphertexts" << endl;
        vector <Ciphertext> permed;
        for (int j=0; j<perm_vec.size(); j++){
            permed.push_back(res_ctxts[perm_vec[j]]);
        }

        //the CS and TA interacts with each other to perform comparisons
        cout << "Performing the argamx protocol..." << endl;
        srand (time(NULL));

        //TA
        long index = 0;  //for keeping track of the index with the higest prob.
        
        //CS
        Ciphertext max = permed[0];

        for (int j=1; j<class_num;j++){

            //timer.set();

            //CS
            Ciphertext current = permed[j];
            parms_id_type max_parms_id = max.parms_id();
            
            current.scale() = max.scale();

            evaluator.mod_switch_to_inplace(current, max_parms_id);


            Ciphertext ct_diff = current;
            evaluator.sub_inplace(ct_diff, max);
            parms_id_type cur_parms_id = ct_diff.parms_id();

            double c = (double) rand()/RAND_MAX, fMin = 0.1, fMax = 100.0;
            double coeff = fMin + c * (fMax - fMin);
            Plaintext plain_coeff;
            encoder.encode(coeff, scale, plain_coeff);
            evaluator.mod_switch_to_inplace(plain_coeff, cur_parms_id);

            evaluator.multiply_plain_inplace(ct_diff, plain_coeff);
            evaluator.rescale_to_next_inplace(ct_diff);
            //only ct_diff is to be sent to the TA

            //TA
            Plaintext plain_diff;
            decryptor.decrypt(ct_diff, plain_diff);
            vector <double> diff;
            encoder.decode(plain_diff, diff);
            
            double b;
            if (diff[0] > 0){ b = 1; index = j;}
            else b = 0;
            vector <double> vec_b(num_slots, b);

            Plaintext plain_b;
            encoder.encode(b, scale, plain_b);
            Ciphertext ct_b;
            encryptor.encrypt(plain_b, ct_b);
            //TA returns this ct_b to the CS            

            //CS
            Ciphertext cur_max = max;

            //calculate ct_b*current -> current
            parms_id_type current_parms_id = current.parms_id();
            evaluator.mod_switch_to_inplace(ct_b, current_parms_id);
            evaluator.multiply_inplace(current, ct_b);
            evaluator.relinearize_inplace(current, relin_keys);
            evaluator.rescale_to_next_inplace(current);

            //calculate (1-b)
            Plaintext plain_one;
            encoder.encode(1, scale, plain_one);
            parms_id_type ct_b_parms_id = ct_b.parms_id();
            evaluator.mod_switch_to_inplace(plain_one, ct_b_parms_id);
            evaluator.negate_inplace(ct_b);
            evaluator.add_plain_inplace(ct_b, plain_one);

            //calculate (1-b)*cur_max -> cur_max
            parms_id_type cur_max_parms_id = cur_max.parms_id();
            evaluator.mod_switch_to_inplace(ct_b, cur_max_parms_id);
            evaluator.multiply_inplace(cur_max, ct_b);
            evaluator.relinearize_inplace(cur_max, relin_keys);
            evaluator.rescale_to_next_inplace(cur_max);

        
            evaluator.add_inplace(cur_max, current);
            max = cur_max;

            //double cTime = timer.get();
            //myfile << cTime << "\n" << flush;
        }

        cout << "Finished" << endl;
        cout << endl;

        //TA sends the index to the client as the final result
        cout << "Index after permutation: " << index << endl;
        long depermed = perm_vec[index];
        cout << "Classification result index: " << depermed << endl;
        cout << "Classification result: " << info.class_names[depermed] << endl;
        myfile2 << info.class_names[depermed] << "\n" << flush;

        cout << endl;

        double cTime = timer.get();
        myfile << cTime << "\n" << flush;
        timer.print("Time for classifying one data: ");
        cout << endl;
        
    }

    myfile << "\n" << flush;
    myfile << "Finished classifying all data \n" << flush;
    myfile.close();

    return 0;
}
