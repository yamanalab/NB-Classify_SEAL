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

    int num_probs = info.num_features + 1;
    int num_data = num_slots/num_probs;
    cout << "Maximum number of data that can be packed into a ciphertext: " << num_data << endl;
    int shiftIndex = num_data*(num_probs-1);

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
    cout << "Total number of data: " << orig_data.size() << endl;

    //parsing data 
    vector <vector <double> > data;
    for (int i=0; i<orig_data.size(); i++){
        vector <double> temp = {1};
        vector <double> temp2 = parseData(orig_data[i], info.attr_values);
        temp.insert(temp.end(), temp2.begin(), temp2.end());
        temp.resize(num_slots);
        data.push_back(temp);
        //printVector(temp);
    }
    cout << "Finished processing data" << endl;
    cout << endl;

    ////////////////////////////////////////////////////////////////////////////

    string filename = "results/classifyMult_"+dataset+to_string(class_num)+".csv";
    ofstream myfile;
    myfile.open(filename);

    string filename2 = "results/result.txt";
    ofstream myfile2;
    myfile2.open(filename2);

    //int num_test = 1;
    int num_test = (data.size()/num_data)+1;
    for (int i = 0; i<num_test; i++){
        timer.set();

        cout << "Classifying a query: " << i << endl;

        // Client generating the query by encrypting data and generating a permutation vector
        //Packing and encrypting data to be classified        
        vector <double> to_enc (num_slots, 0);
        int to_pack;
        int left = data.size()-(num_data*i);
        if (left > num_data){ to_pack = num_data; }
        else { to_pack = left; }

        for (int j = 0; j<to_pack; j++){
            for (int k = 0; k<num_probs; k++){
                to_enc[(j*num_probs)+k] = data[j+(num_data*i)][k];
            }
        }

        Plaintext cur;
        encoder.encode(to_enc, scale, cur);
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
            sumAll(evaluator, res, gal_keys, num_probs);
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
        vector <long> index (to_pack, 0);  //for keeping track of the index with the higest prob.
        
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

            //generate a masking vector
            vector <double> mask(num_slots, 0);
            for (int k=1; k<=to_pack; k++){
                double c = (double) rand()/RAND_MAX, fMin = 0.1, fMax = 100.0;
                double coeff = fMin + c * (fMax - fMin);
                mask[(num_probs*k)-1] = coeff;
            }
            Plaintext plain_coeff;
            encoder.encode(mask, scale, plain_coeff);
            evaluator.mod_switch_to_inplace(plain_coeff, cur_parms_id);
            
            evaluator.multiply_plain_inplace(ct_diff, plain_coeff);
            evaluator.rescale_to_next_inplace(ct_diff);

            //only ct_diff is to be sent to the TA

            //TA
            Plaintext plain_diff;
            decryptor.decrypt(ct_diff, plain_diff);
            vector <double> diff;
            encoder.decode(plain_diff, diff);


            vector <double> vec_b (num_slots, 0);
            for (int k=1; k<=to_pack; k++){
                double b;
                if (diff[(num_probs*k)-1] > 0){ b = 1; index[k-1] = j;}
                else b = 0;
                vec_b[(num_probs*k)-1] = b;
            }
            Plaintext plain_b;
            encoder.encode(vec_b, scale, plain_b);
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
        cout << "Index after permutation: " << endl;
        printVector(index);
        vector <long> depermed (to_pack, 0);
        vector <string> result (to_pack);
        for (int k=0; k<to_pack; k++){
            int cur = perm_vec[index[k]];
            depermed[k] = cur;
            result[k] = info.class_names[cur];
            myfile2 << info.class_names[cur] << "\n" << flush;
        }
        cout << "Classification result index: " << endl;
        printVector(depermed);
        cout << "Classification result: " << endl;
        printVector(result);

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
