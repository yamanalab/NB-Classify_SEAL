#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <random>
#include "tools.h"
#include "seal/seal.h"
 
using namespace std;
using namespace seal;

Model readModel (string filename, vector <string> class_names, vector <vector <string> > attr_values){
  Model NB;
  NB.class_num = class_names.size(); //Number of classes
  NB.feature_num = attr_values.size(); //Number of features
  //cout << "Number of features: " << NB.feature_num << endl;
  NB.feature_value_num; //Number of possible values per feature
  for (int i = 0; i<NB.feature_num; i++){
    NB.feature_value_num.push_back(attr_values[i].size());
  } // array that contains number of possible values for each attribute

  ifstream infile(filename);
  string line;

  double num;
  int count = 0;
  int class_count = -1;

  while (getline(infile, line)){
      stringstream ss(line);

      //Reads class probabilities into class_prob
      if (count == 0){
        while (ss >> num){
          vector <double> temp;
          temp.push_back(num);
          NB.probs.push_back(temp);
          if (ss.peek()== ','){ss.ignore();}
        }
      }
      else if (((NB.feature_num*class_count)+2+class_count <= count) && (count <= ((NB.feature_num*class_count)+1+class_count+NB.feature_num))){
        while (ss >> num){
          NB.probs[class_count].push_back(num);
          if (ss.peek()== ','){ss.ignore();}
        }
      }

      else {class_count += 1;}

      count += 1;
    }
    return NB;
}

void printModel(Model NB){
  int class_num = NB.probs.size();
  cout << "Printing the trained model..." << endl;

  cout << "Class probability" << endl;
  for (int i = 0; i<class_num; i++){
    cout << "Class " + to_string(i) + ": " << NB.probs[i][0] << endl;
  }
  cout << endl;

  cout << "Conditional probability";
  for (int i = 0; i<class_num; i++){
    cout << endl;
    cout << "Class " + to_string(i) << ": " << endl;
    printVector(NB.probs[i]);
    cout << endl;
  }
}

Info readInfo(string filename){
  Info info;

  ifstream infile(filename);
  string line;
  int count = 0;
  info.num_features = 0;

  while (getline(infile, line)){
      stringstream ss(line);

      if (count == 0){
        count++;
        while (ss.good()){
          string substr;
          getline(ss, substr, ',');
          info.class_names.push_back(substr);
        }
      }

      else {
        vector <string> temp;
        while (ss.good()){
          string substr;
          getline(ss, substr, ',');
          temp.push_back(substr);
        }
        info.num_features += temp.size();
        info.attr_values.push_back(temp);
      }
  }
  info.class_num = info.class_names.size();

  return info;

}

vector <vector <string> > readData(string filename){
  vector <vector <string> > data;
  ifstream infile(filename);
  string line;

  while (getline(infile, line)){
    vector <string> temp;
    stringstream ss(line);
    string value;

    while (getline(ss, value, ',')){
      temp.push_back(value);
    }

    temp.pop_back(); //pops out the class label
    data.push_back(temp);
  }
  infile.close();
  return data;
}

void printAllData(vector <vector <string> >& data){
  cout << "Printing test data" << endl;
  for(int i=0; i < data.size(); i++){
      cout << "Data " << i << ": " << endl;
      printVector(data[i]);
      cout << endl;
    }
}

vector <double> parseData(vector <string> sample, vector <vector <string> > attr_values){
  vector <double> parsed;
    for (int i =0; i < sample.size(); i++){
      int length = attr_values[i].size();
    
      for (int j=0; j < attr_values[i].size(); j++){
        if (sample[i] == attr_values[i][j]){ parsed.push_back(1); }
        else { parsed.push_back(0); }
      }
    }

    return parsed;
}

vector <long> genPermVec (int n){
  vector <long> perm_vec (n);
  iota(perm_vec.begin(), perm_vec.end(), 0);

  random_device seed_gen;
  mt19937 engine(seed_gen());
  shuffle(perm_vec.begin(), perm_vec.end(), engine);

  return perm_vec;
}

vector <long> readPermVec(string filename){
  vector <long> perm_vec;
  ifstream infile(filename);
  string line;

  while (getline(infile, line)){
    stringstream ss(line);
    int num;

    while (ss >> num){
          perm_vec.push_back(num);
          if (ss.peek()== ','){ss.ignore();}
        }
  }
  return perm_vec;
}

PublicKey loadPK(string filename){
  ifstream pkFile(filename);
  PublicKey public_key;
  public_key.unsafe_load(pkFile);
  pkFile.close();
  return public_key;
}

SecretKey loadSK(string filename){
  ifstream skFile(filename);
  SecretKey secret_key;
  secret_key.unsafe_load(skFile);
  skFile.close();
  return secret_key;
}

GaloisKeys loadGK(string filename){
  ifstream galFile(filename);
  GaloisKeys gal_keys;
  gal_keys.unsafe_load(galFile);
  galFile.close();
  return gal_keys;
}

RelinKeys loadRK(string filename){
  ifstream relinFile(filename);
  RelinKeys relin_keys;
  relin_keys.unsafe_load(relinFile);
  relinFile.close();
  return relin_keys;
}

void writeCtxt(string filename, Ciphertext ctxt){
  ofstream ctxtFile(filename, ios::binary);
  ctxt.save(ctxtFile);
  ctxtFile.close();
}

Ciphertext loadCtxt(string filename, shared_ptr<SEALContext> context){
  fstream CtxtFile(filename, fstream::in);
  Ciphertext ctxt;
  ctxt.load(context, CtxtFile);
  CtxtFile.close();
  return ctxt;
}

long numBits(long n){
  long k = 0;
  while (n > 0){k++; n /= 2;}
  return k;
}

bool curBit(long n, long i){
  long masked = n&(1 << i);
  //cout << "n: " << n << ", i: " << i << endl;
  //cout << masked << endl;
  if (masked != 0){return true;}
  else{return false;}
}

void sumAll(Evaluator& evaluator, Ciphertext& ctxt, GaloisKeys& gal_keys, long n){
  if (n == 1) return;

  Ciphertext orig = ctxt;
  long k = numBits(n), e = 1;

  for (long i = k-2; i >= 0; i--){
    Ciphertext temp1 = ctxt;
    evaluator.rotate_vector_inplace(temp1, -e, gal_keys);
    evaluator.add_inplace(ctxt, temp1);
    e *= 2;

    if (curBit(n, i)){
      Ciphertext temp2 = orig;
      evaluator.rotate_vector_inplace(temp2, -e, gal_keys);
      evaluator.add_inplace(ctxt, temp2);
      e += 1;
    }
  }
}
